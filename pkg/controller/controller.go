package controller

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
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
	cgroupfs      string
	bpffs         string
	gwAddr        uint32
	gwIfAddr      uint32
	allowedDNS    []uint32
	dnsCache      *dnscache.Cache
	fqdnStore     *fqdn.Cache
	dnsproxy      *dnsproxy.DNSProxy
	ringbufReader *ringbuf.Reader

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
	// needs to be in sync with cgroup_skb.c
	// TODO: pull these settings from bytecode so there's no need to sync
	ActionAllow = uint32(1)

	// Name of the directory in /sys/fs/bpf that holds the pinned maps/progs
	BPFMountDir = "skouter"

	logger = log.DefaultLogger.WithName("controller")
)

func New(
	ctx context.Context,
	k8sConfig *rest.Config,
	cgroupfs,
	bpffs,
	nodeName,
	nodeIP,
	cacheStoragePath string,
	allowedDNS []string,
	auditMode bool) (*Controller, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var dnsAddrs []uint32
	for _, dnsAddr := range allowedDNS {
		dnsIP := net.ParseIP(dnsAddr)
		if dnsIP == nil {
			return nil, fmt.Errorf("invalid ip addr: %s", dnsIP)
		}
		dnsAddrs = append(dnsAddrs, binary.LittleEndian.Uint32(dnsIP.To4()))
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

		cgroupfs:   cgroupfs,
		bpffs:      bpffs,
		allowedDNS: dnsAddrs,
		gwAddr:     binary.LittleEndian.Uint32(gwAddr.To4()),
		gwIfAddr:   binary.LittleEndian.Uint32(gwIfAddr.To4()),
		dnsCache:   dnscache.New(),
		fqdnStore:  fqdnCache,
		nodeName:   nodeName,
		nodeIP:     nodeIP,
		auditMode:  auditMode,
		idxMu:      &sync.RWMutex{},
		hostIdx:    indices.HostIndex{},
	}

	err = ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	ctrl.ringbufReader, err = ringbuf.NewReader(ctrl.bpf.EventsMap)
	if err != nil {
		return nil, err
	}
	ctrl.dnsproxy, err = dnsproxy.NewProxy(ctrl.ringbufReader, ctrl.dnsCache, fqdnCache, ctrl.AllowHost)
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

	// set the upstream dns server
	logger.Info("setting allowed dns", "allowed-ips", c.allowedDNS)
	for _, addr := range c.allowedDNS {
		err := c.bpf.DNSConfig.Put(addr, ActionAllow) // value isn't used
		if err != nil {
			return fmt.Errorf("unable to set dns config: %w", err)
		}
	}

	// start to listen for updates
	go c.readUpdates()

	// pre-warm DNS cache and allow-list IPs
	err = c.preWarm()
	if err != nil {
		return fmt.Errorf("unable to prewarm: %s", err)
	}
	go c.dnsproxy.Start()

	logger.Info("attaching progs", "dir", c.cgroupfs)
	// attach the program to cgroup
	return c.bpf.Attach(c.cgroupfs)
}

func (c *Controller) readUpdates() {
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
	logger.Info("unblocking resolved addr", "daddr", keyToIP(resolvedAddr), "key", keyToIP(key))

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
	addrIdx := make(indices.AddressIndex)
	cidrIdx := make(indices.CIDRIndex)
	hostIdx := make(indices.HostIndex)
	ruleIdx := make(indices.RuleIndex)
	unstructured, err := c.k8sDynClient.Resource(v1alpha1.EgressGroupVersionResource).List(c.ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, unstructuredEgress := range unstructured.Items {
		var egress v1alpha1.Egress
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(unstructuredEgress.Object, &egress)
		if err != nil {
			return err
		}

		// prepare allowed egress ips
		hosts := []string{}
		egressIPs := map[uint32]uint32{}
		egressCIDRs := map[string]*net.IPNet{}
		egressRegexs := map[string]*regexp.Regexp{}

		for _, rule := range egress.Spec.Rules {
			hosts = append(hosts, rule.Domains...)
			// add static ips
			for _, ip := range rule.IPs {
				key := keyForAddr(net.ParseIP(ip))
				egressIPs[key] = ActionAllow
			}
			// add dynamic ips (without fqdns)
			for _, domain := range rule.Domains {
				addrs := c.dnsCache.Lookup(domain)
				if addrs == nil {
					continue
				}
				for addr := range addrs {
					egressIPs[addr] = ActionAllow
				}
			}

			for _, cidr := range rule.CIDRs {
				_, net, err := net.ParseCIDR(cidr)
				if err != nil {
					logger.Error(err, "unable to parse cidr", "cidr", cidr)
					continue
				}
				egressCIDRs[net.String()] = net
			}

			for _, reRule := range rule.Regexps {
				re, err := regexp.Compile(reRule)
				if err != nil {
					logger.Error(err, "unable to compile regexp", "rule", reRule)
					continue
				}
				egressRegexs[reRule] = re
			}
		}

		// add allowed dns servers
		for _, addr := range c.allowedDNS {
			egressIPs[addr] = ActionAllow
		}

		// add localhost CIDR 127.0.0.1/8
		egressCIDRs["127.0.0.1/8"] = &net.IPNet{
			IP:   net.IP{0x7f, 0x0, 0x0, 0x0},
			Mask: net.IPMask{0xff, 0x0, 0x0, 0x0}}

		// handle host firewall
		if egress.Spec.NodeSelector != nil {
			// check if node matches selector
			node, err := c.k8sClientSet.CoreV1().Nodes().Get(c.ctx, c.nodeName, metav1.GetOptions{})
			if err != nil {
				continue
			}
			sel := labels.SelectorFromValidatedSet(labels.Set(egress.Spec.NodeSelector.MatchLabels))
			if !sel.Matches(labels.Set(node.ObjectMeta.Labels)) {
				logger.V(1).Info("egress node selector doesn't match labels of this node", "egress", egress.ObjectMeta.Name)
				continue
			}

			key := keyForAddr(net.ParseIP(c.nodeIP))
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if ruleIdx[key] == nil {
				ruleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// host firewall needs to be allowed to send traffic to
			// the default gateway and to localhost
			egressIPs[c.gwAddr] = ActionAllow
			egressIPs[c.gwIfAddr] = ActionAllow

			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(ruleIdx[key], egressRegexs)

			for _, hostname := range hosts {
				if hostIdx[hostname] == nil {
					hostIdx[hostname] = make(map[uint32]struct{})
				}
				hostIdx[hostname][key] = struct{}{}
			}
			continue
		}

		podList, err := c.k8sClientSet.CoreV1().Pods("").List(c.ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + c.nodeName,
			LabelSelector: labels.FormatLabels(egress.Spec.PodSelector.MatchLabels),
		})
		if err != nil {
			return fmt.Errorf("unable to list pods: %w", err)
		}

		// for every pod: prepare address and hostname indices
		// so we can do a lookup by pod key
		for _, pod := range podList.Items {
			// we do not want to apply policies for pods
			// that are on the host network.
			if pod.Status.PodIP == "" || pod.Spec.HostNetwork {
				continue
			}
			podIP := net.ParseIP(pod.Status.PodIP)
			if podIP == nil {
				logger.Error(err, "unable to parse ip", "addr", pod.Status.PodIP)
				continue
			}
			key := keyForAddr(podIP)
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if ruleIdx[key] == nil {
				ruleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(ruleIdx[key], egressRegexs)

			for _, host := range hosts {
				// we need to normalize this to a fqdn
				hostname := host
				if !strings.HasSuffix(host, ".") {
					hostname += "."
				}
				if hostIdx[hostname] == nil {
					hostIdx[hostname] = make(map[uint32]struct{})
				}
				hostIdx[hostname][key] = struct{}{}
				mergeHostMap(addrIdx[key], c.dnsCache.Lookup(hostname))
			}
		}
	}

	c.idxMu.Lock()
	c.addrIdx = addrIdx
	c.cidrIdx = cidrIdx
	c.hostIdx = hostIdx
	c.ruleIdx = ruleIdx
	c.idxMu.Unlock()

	c.dnsproxy.UpdateAllowed(hostIdx, ruleIdx, cidrIdx)
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
