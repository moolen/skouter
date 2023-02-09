package controller

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jackpal/gateway"
	v1alpha1 "github.com/moolen/skouter/api"
	"github.com/moolen/skouter/pkg/bpf"
	dnscache "github.com/moolen/skouter/pkg/cache/dns"
	"github.com/moolen/skouter/pkg/cache/fqdn"
	"github.com/moolen/skouter/pkg/dnsproxy"
	"github.com/moolen/skouter/pkg/indices"
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/metrics"
	"github.com/moolen/skouter/pkg/util"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Controller struct {
	ctx context.Context

	k8sConfig    *rest.Config
	k8sClientSet *kubernetes.Clientset
	k8sDynClient *dynamic.DynamicClient

	bpf           *bpf.LoadedCollection
	auditMode     bool
	nodeName      string
	nodeIP        string
	updateChan    chan struct{}
	netDeviceName string
	bpffs         string
	gwAddr        uint32
	gwIfAddr      uint32

	trustedDNSEndpoint        string
	trustedDNSEndpointService string
	dnsCache                  *dnscache.Cache
	fqdnStore                 *fqdn.Cache
	dnsproxy                  *dnsproxy.DNSProxy
	ringbufReader             *ringbuf.Reader

	idxMu *sync.RWMutex
	// hostIdx is a map: hostname => map[pod-key]=>allowed-state
	hostIdx indices.HostIndex
	// ruleIdx is a map addr => map[re-rule]=>*regexp.Regexp
	ruleIdx indices.RuleIndex
	// addrIdx is a map pod-key => map[upstream-ip]=>allowed-state
	addrIdx indices.AddressIndex
	// cidrIdx is a map pod-key => map[cidr-string] => net.IPNet CIDR
	cidrIdx indices.CIDRIndex
}

var (
	// Action used by the bpf program
	// needs to be in sync with egress.c
	// TODO: pull these settings from bytecode so there's no need to sync
	ActionAllow = uint32(1)

	// Name of the directory in /sys/fs/bpf that holds the pinned maps/progs
	BPFMountDir = "skouter"

	logger = log.DefaultLogger.WithName("controller")
)

func New(
	ctx context.Context,
	k8sConfig *rest.Config,
	netDeviceName,
	bpffs,
	nodeName,
	nodeIP,
	cacheStoragePath,
	trustedDNSEndpoint,
	trustedDNSEndpointService string,
	auditMode bool) (*Controller, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	// TODO: make that configurable/extensible through CLI
	//       a user may need to specify an IP address from a different interface
	gwAddr, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	gwIfAddr, err := gateway.DiscoverInterface()
	if err != nil {
		return nil, err
	}

	logger.Info("discovered", "gw", gwAddr.String(), "gw-interface", gwIfAddr.String())

	fqdnCache := fqdn.New(cacheStoragePath)
	fqdnCache.Restore()
	go fqdnCache.Autosave(ctx, time.Second*15)

	clientSet, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	ctrl := &Controller{
		ctx:          ctx,
		k8sConfig:    k8sConfig,
		k8sClientSet: clientSet,
		k8sDynClient: dynClient,
		updateChan:   make(chan struct{}),

		netDeviceName:             netDeviceName,
		bpffs:                     bpffs,
		trustedDNSEndpoint:        trustedDNSEndpoint,
		trustedDNSEndpointService: trustedDNSEndpointService,
		gwAddr:                    binary.LittleEndian.Uint32(gwAddr.To4()),
		gwIfAddr:                  binary.LittleEndian.Uint32(gwIfAddr.To4()),
		dnsCache:                  dnscache.New(),
		fqdnStore:                 fqdnCache,
		nodeName:                  nodeName,
		nodeIP:                    nodeIP,
		auditMode:                 auditMode,
		idxMu:                     &sync.RWMutex{},
		hostIdx:                   indices.HostIndex{},
	}

	err = ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	ctrl.ringbufReader, err = ringbuf.NewReader(ctrl.bpf.EventsMap)
	if err != nil {
		return nil, err
	}
	ctrl.dnsproxy, err = dnsproxy.NewProxy(ctrl.ringbufReader, ctrl.dnsCache, fqdnCache, ctrl.AllowHost, ctrl.nodeIP, trustedDNSEndpoint)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}

func (c *Controller) Run() error {
	metrics.NewCollector(c.bpf.MetricsMap, c.bpf.MetricsBlockedAddr, c.nodeName)

	err := c.startPodWatcher()
	if err != nil {
		return fmt.Errorf("unable to start pod watcher: %w", err)
	}
	err = c.startEgressWatcher()
	if err != nil {
		return fmt.Errorf("unable to start egress watcher: %w", err)
	}

	// == initialisation process ==
	//
	// Before we _enforce_ egress traffic
	// we must ensure that pre-existing connections to allowed hosts
	// won't be impacted by us.
	//
	// To do so we'll issue DNS queries to find allowed IP addresses
	// and store them before we block traffic.
	//
	// 1. do not block egress traffic
	// 2. query & store allowed hosts' IP addresses
	// 3. block egress.
	err = c.configureMaps()
	if err != nil {
		return err
	}

	// start to listen for updates
	go c.reconcileEgressResources()

	// pre-warm DNS cache and allow-list IPs
	err = c.preWarm()
	if err != nil {
		return fmt.Errorf("unable to prewarm: %s", err)
	}

	go c.dnsproxy.Start()
	return c.bpf.Attach(c.netDeviceName)
}

func (c *Controller) configureMaps() error {
	// add statically configured trusted DNS server
	addr, port, err := net.SplitHostPort(c.trustedDNSEndpoint)
	if err != nil {
		return err
	}
	dnsIP := net.ParseIP(addr)
	dnsPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("unable to convert %s to int: %w", port, err)
	}
	err = c.addAllowedDNS(dnsIP, dnsPort)
	if err != nil {
		return err
	}

	err = c.kubeDNSEndpointWatch()
	if err != nil {
		return err
	}

	lnk, err := netlink.LinkByName(c.netDeviceName)
	if err != nil {
		return err
	}
	proxyCfg := bpf.ProxyRedirectConfig{
		Addr:    util.IPToUint(net.ParseIP(c.nodeIP)),
		Ifindex: uint16(lnk.Attrs().Index),
	}
	logger.Info("setting proxy redirect map", "config", proxyCfg, "map value size", c.bpf.ProxyRedirectMap.ValueSize())
	err = c.bpf.ProxyRedirectMap.Put(uint32(0), &proxyCfg)
	if err != nil {
		return fmt.Errorf("unable to update proxy redirect map: %w", err)
	}
	dmac := bpf.ProxyRedirectDMAC{
		Dmac1: binary.LittleEndian.Uint32([]byte{
			lnk.Attrs().HardwareAddr[0],
			lnk.Attrs().HardwareAddr[1],
			lnk.Attrs().HardwareAddr[2],
			lnk.Attrs().HardwareAddr[3]}),
		Dmac2: binary.LittleEndian.Uint16([]byte{
			lnk.Attrs().HardwareAddr[4],
			lnk.Attrs().HardwareAddr[5]}),
	}
	err = c.bpf.ProxyRedirectDMACMap.Put(uint32(0), &dmac)
	if err != nil {
		return fmt.Errorf("unable to update proxy redirect dmac map: %w", err)
	}

	for _, cookie := range c.dnsproxy.UpstreamSocketCookies {
		err = c.bpf.ProxySocketCookieMap.Put(cookie, uint32(1))
		if err != nil {
			return fmt.Errorf("unable to update proxy socket cookie map: %w", err)
		}
	}

	return nil
}

func (c *Controller) addAllowedDNS(ip net.IP, port int) error {
	if ip == nil || port == 0 {
		return fmt.Errorf("cannot allow empty ip or port=0")
	}
	dnsConfigKey := bpf.DNSServerEndpoint{
		Addr: util.IPToUint(ip),
		Port: util.ToNetBytes16(uint16(port)),
	}
	logger.V(2).Info("add allowed dns endpoint", "config", dnsConfigKey)
	err := c.bpf.DNSConfig.Put(&dnsConfigKey, ActionAllow)
	if err != nil {
		return fmt.Errorf("unable to set dns config: %w", err)
	}
	return nil
}

func (c *Controller) deleteAllowedDNS(ip net.IP, port int) error {
	if ip == nil || port == 0 {
		return fmt.Errorf("cannot allow empty ip or port=0")
	}
	dnsConfigKey := bpf.DNSServerEndpoint{
		Addr: util.IPToUint(ip),
		Port: util.ToNetBytes16(uint16(port)),
	}
	logger.V(2).Info("deleting allowed dns endpoint", "config", dnsConfigKey)
	err := c.bpf.DNSConfig.Delete(&dnsConfigKey)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unable to set dns config: %w", err)
	}
	return nil
}

func (c *Controller) kubeDNSEndpointWatch() error {
	if c.trustedDNSEndpoint == "" {
		return nil
	}
	fields := strings.Split(c.trustedDNSEndpointService, "/")
	if len(fields) != 2 {
		return fmt.Errorf("unable to parse trustend service endpoint %q: unexpected format. expected <namespace>/<service>", c.trustedDNSEndpointService)
	}
	ns := strings.TrimSpace(fields[0])
	svc := strings.TrimSpace(fields[1])
	watcher, err := c.k8sClientSet.CoreV1().Endpoints(ns).Watch(c.ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + svc,
	})
	if err != nil {
		return err
	}

	go func() {
		logger.Info("watching dns service endpoints", "namespace", ns, "service", svc)
		for {
			select {
			case <-c.ctx.Done():
				return
			case ev := <-watcher.ResultChan():
				if ev.Object == nil {
					continue
				}
				logger.Info("received endpoint event", "event", ev)
				ep, ok := ev.Object.(*corev1.Endpoints)
				if !ok {
					logger.Error(fmt.Errorf("unexpected watch object %#v", ev.Object), "")
					continue
				}

				if ev.Type == watch.Deleted {
					for _, s := range ep.Subsets {
						for _, addr := range s.Addresses {
							ip := net.ParseIP(addr.IP)
							for _, port := range s.Ports {
								if port.Protocol == corev1.ProtocolUDP {
									err = c.deleteAllowedDNS(ip, int(port.Port))
									if err != nil {
										logger.Error(err, "unable to delete allowed dns ")
									}
								}
							}
						}
					}
				}
				if ev.Type == watch.Added || ev.Type == watch.Modified {
					for _, s := range ep.Subsets {
						for _, addr := range s.Addresses {
							ip := net.ParseIP(addr.IP)
							for _, port := range s.Ports {
								if port.Protocol == corev1.ProtocolUDP {
									err = c.addAllowedDNS(ip, int(port.Port))
									if err != nil {
										logger.Error(err, "unable to delete allowed dns ")
									}
								}
							}
						}
					}
				}
			}
		}
	}()
	return nil
}

func (c *Controller) reconcileEgressResources() {
	update := debounceCallable(time.Second*5, func() {
		err := c.updateConfig()
		if err != nil {
			logger.Error(err, "unable to update config")
		}
	})
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.updateChan:
			update()
		}
	}
}

func debounceCallable(interval time.Duration, f func()) func() {
	var timer *time.Timer
	var lastInvocation time.Time

	return func() {
		if timer != nil {
			timer.Stop()
		}
		// first call or call after longer period of time is immediate
		if time.Since(lastInvocation) > interval {
			f()
			lastInvocation = time.Now()
			return
		}

		timer = time.AfterFunc(interval, func() {
			f()
			lastInvocation = time.Now()
		})
	}
}

func (c *Controller) loadBPF() error {
	pinPath := filepath.Join(c.bpffs, BPFMountDir)
	err := os.MkdirAll(pinPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create bpf fs subpath: %+v", err)
	}

	coll, err := bpf.Load(pinPath, c.auditMode)
	if err != nil {
		return fmt.Errorf("failed to load bpf maps: %+v", err)
	}

	c.bpf = coll

	return err
}

func (c *Controller) startPodWatcher() error {
	podWatch, err := c.k8sClientSet.CoreV1().Pods("").Watch(c.ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + c.nodeName,
	})
	if err != nil {
		return err
	}
	go func() {
		logger.Info("starting pod watcher")
		for {
			select {
			case ev := <-podWatch.ResultChan():
				if ev.Type == watch.Error || ev.Type == "" {
					continue
				}
				c.updateChan <- struct{}{}
			case <-c.ctx.Done():
				logger.Info("shutdown pod watcher")
				return
			}
		}
	}()

	return nil
}

func (c *Controller) startEgressWatcher() error {
	egressWatch, err := c.k8sDynClient.Resource(v1alpha1.EgressGroupVersionResource).Watch(c.ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	go func() {
		logger.Info("starting egress watcher")
		for {
			select {
			case ev := <-egressWatch.ResultChan():
				if ev.Type == watch.Error || ev.Type == "" {
					continue
				}
				c.updateChan <- struct{}{}
			case <-c.ctx.Done():
				logger.Info("shutdown egress watcher")
				return
			}
		}
	}()
	return nil
}

func (c *Controller) preWarm() error {
	logger.Info("starting prewarm")
	// prepare bpf maps
	err := c.updateConfig()
	if err != nil {
		return fmt.Errorf("update config: %s", err)
	}

	c.idxMu.RLock()
	hostIdx := c.hostIdx.Clone()
	c.idxMu.RUnlock()

	logger.Info("prewarm host indices")
	for host, podKeys := range hostIdx {
		addrs := c.dnsCache.LookupIP(host)
		for _, addr := range addrs {
			hostAddr := addr.To4()
			if hostAddr == nil {
				continue
			}
			for podKey := range podKeys {
				err = c.AllowHost(podKey, hostAddr)
				if err != nil {
					logger.Error(err, "unable to allow host")
				}
			}
		}
	}

	logger.Info("done with prewarm")
	return nil
}

func (c *Controller) AllowHost(key uint32, addr net.IP) error {
	resolvedAddr := binary.LittleEndian.Uint32(addr)
	logger.V(3).Info("unblocking resolved addr", "daddr", keyToIP(resolvedAddr), "key", keyToIP(key))

	var innerID ebpf.MapID
	err := c.bpf.EgressConfig.Lookup(key, &innerID)
	if err != nil {
		return fmt.Errorf("unable to lookup outer map: %s", err.Error())
	}
	innerMap, err := ebpf.NewMapFromID(innerID)
	if err != nil {
		return fmt.Errorf("unable to create inner map from fd: %s", err.Error())
	}
	err = innerMap.Put(&resolvedAddr, &ActionAllow)
	if err != nil {
		return fmt.Errorf("unable to put map: %s", err.Error())
	}
	return nil
}

func (c *Controller) updateConfig() error {
	logger.V(1).Info("updating config")
	start := time.Now()
	defer metrics.ReconcileMaps.With(nil).Observe(time.Since(start).Seconds())
	if err := c.updateIndices(); err != nil {
		return err
	}

	// reconcile bpf maps
	wcstart := time.Now()
	if err := c.fqdnStore.ReconcileIndex(c.flattenRules()); err != nil {
		return err
	}
	metrics.ReconcileRegexpCache.With(nil).Observe(time.Since(wcstart).Seconds())
	if err := c.reconcileAddrMap(); err != nil {
		return err
	}
	return c.reconcileCIDRMap()
}

func (c *Controller) updateIndices() error {
	start := time.Now()
	defer metrics.UpdateIndices.With(nil).Observe(time.Since(start).Seconds())

	addrIdx, cidrIdx, hostIdx, ruleIdx, err := indices.Generate(
		c.ctx, c.k8sDynClient, c.k8sClientSet, c.dnsCache,
		c.trustedDNSEndpoint, c.nodeIP, c.nodeName, c.gwAddr, c.gwIfAddr,
	)
	if err != nil {
		return err
	}

	c.idxMu.Lock()
	c.addrIdx = addrIdx
	c.cidrIdx = cidrIdx
	c.hostIdx = hostIdx
	c.ruleIdx = ruleIdx
	c.idxMu.Unlock()

	c.dnsproxy.UpdateAllowed(hostIdx, ruleIdx)
	return nil
}

func (c *Controller) Close() {
	logger.Info("closing bpf resources")

	// Flush fqdn cache to disk
	// so it can be restored
	err := c.fqdnStore.Save()
	if err != nil {
		logger.Error(err, "unable to save fqdn store")
	}
	c.ringbufReader.Close()
	c.bpf.Close()
}
