package bpf

import (
	"bytes"
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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
	v1alpha1 "github.com/moolen/skouter/api"
	cache "github.com/moolen/skouter/pkg/dns_cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf ./c/cgroup_skb.c -- -I./c/headers
type Controller struct {
	ctx        context.Context
	client     client.Client
	log        logrus.FieldLogger
	auditMode  bool
	nodeName   string
	nodeIP     string
	updateChan chan struct{}
	cgroupfs   string
	bpffs      string
	allowedDNS []uint32
	dnsCache   *cache.Cache

	hostIdxmu *sync.RWMutex
	// hostIdx is a map: hostname => map[pod-key]=>allowed-state
	hostIdx map[string]map[uint32]struct{}

	ingressProg        *ebpf.Program
	egressProg         *ebpf.Program
	egressConfig       *ebpf.Map
	dnsConfig          *ebpf.Map
	eventsMap          *ebpf.Map
	metricsMap         *ebpf.Map
	metricsBlockedAddr *ebpf.Map

	ingressLink link.Link
	egressLink  link.Link
}

var (
	// Action used by the bpf program
	// needs to be in sync with cgroup_skb.c
	// TODO: pull these settings from bytecode so there's no need to sync
	ActionAllow = uint32(1)
	ActionDeny  = uint32(2)

	// inner map must be in sync with cgroup_skb.c
	innerPodMap = &ebpf.MapSpec{
		Name:       "pod_egress_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  4, // 4 bytes for u32
		MaxEntries: 4096,
	}
)

func New(
	ctx context.Context,
	client client.Client,
	cgroupfs,
	bpffs,
	nodeName,
	nodeIP string,
	allowedDNS []string,
	auditMode bool,
	log logrus.FieldLogger,
	updateChan chan struct{},
	reg *prometheus.Registry) (*Controller, error) {
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

	ctrl := &Controller{
		ctx:        ctx,
		log:        log,
		updateChan: updateChan,
		client:     client,
		cgroupfs:   cgroupfs,
		bpffs:      bpffs,
		allowedDNS: dnsAddrs,
		dnsCache:   cache.New(log),
		nodeName:   nodeName,
		nodeIP:     nodeIP,
		auditMode:  auditMode,
		hostIdxmu:  &sync.RWMutex{},
		hostIdx:    make(map[string]map[uint32]struct{}),
	}

	err := ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	newMetricsCollector(reg, ctrl)
	return ctrl, nil
}

func (c *Controller) Run() error {
	// == initialisation process ==
	//
	// Before we _enforce_ egress traffic
	// we must ensure that pre-existing connections to allowed hosts
	// won't be impacted by us.
	//
	// Todo do so we'll issue DNS queries to find allowed IP addresses
	// and store them before we block traffic.
	//
	// 1. do not block egress traffic
	//    This is implemente
	// 2. query & store allowed hosts' IP addresses
	// 3. block egress.

	// set the upstream dns server
	c.log.Infof("setting allowed dns: %d", c.allowedDNS)
	for _, addr := range c.allowedDNS {
		err := c.dnsConfig.Put(addr, uint32(1)) // value isn't used
		if err != nil {
			return fmt.Errorf("unable to set dns config: %w", err)
		}
	}

	// pre-warm eBPF maps with fresh IPs from DNS
	err := c.preWarm()
	if err != nil {
		return err
	}

	// finally attach the program to
	err = c.attach()
	if err != nil {
		return fmt.Errorf("unable to attach to cgroup2: %s", err.Error())
	}

	go c.runDNSReader()
	tt := time.NewTicker(time.Second * 15)
	for {
		select {
		case <-c.ctx.Done():
			return nil
		case <-c.updateChan:
			err := c.updateConfig()
			if err != nil {
				c.log.Error(err)
			}
		case <-tt.C:
			c.dumpMap()
		}
	}
}

func (c *Controller) preWarm() error {
	c.log.Infof("starting prewarm")
	// prepare bpf maps
	err := c.updateConfig()
	if err != nil {
		return err
	}

	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()

	for host, podKeys := range c.hostIdx {
		addrs := c.dnsCache.LookupIP(host)
		for _, addr := range addrs {
			hostAddr := addr.To4()
			if hostAddr == nil {
				continue
			}
			for podKey := range podKeys {
				err = c.tryAllowAddress([]string{host}, []net.IP{hostAddr}, podKey)
				if err != nil {
					c.log.Error(err)
				}
			}
		}
	}

	c.log.Info("done with prewarm")
	return nil
}

func (c *Controller) loadBPF() error {
	pinPath := filepath.Join(c.bpffs, "skouter")
	err := os.MkdirAll(pinPath, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create bpf fs subpath: %+v", err)
	}

	err = c.loadBPFMaps(pinPath)
	if err != nil {
		return fmt.Errorf("failed to load bpf maps: %+v", err)
	}

	err = c.loadBPFProgs(pinPath)
	if err != nil {
		return fmt.Errorf("failed to load bpf progs: %+v", err)
	}

	c.log.Infof("map egress config pinned: %t", c.egressConfig.IsPinned())
	c.log.Infof("map dns config pinned: %t", c.dnsConfig.IsPinned())

	return err
}

func (c *Controller) loadBPFMaps(pinPath string) error {
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	c.log.Infof("pinning ebpf maps to: %s", pinPath)
	err = spec.LoadAndAssign(&objs.bpfMaps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to load bpf: %s", err.Error())
	}

	c.egressConfig = objs.bpfMaps.EgressConfig
	c.dnsConfig = objs.bpfMaps.DnsConfig
	c.metricsMap = objs.bpfMaps.Metrics
	c.metricsBlockedAddr = objs.bpfMaps.MetricsBlockedAddr
	c.eventsMap = objs.bpfMaps.Events

	return nil
}

func (c *Controller) loadBPFProgs(pinPath string) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	objs := bpfObjects{}
	if c.auditMode {
		spec.RewriteConstants(map[string]interface{}{
			"audit_mode": uint32(1),
		})
	}

	err = spec.LoadAndAssign(&objs.bpfPrograms, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ebpf.ProgramOptions{
			LogSize: 1024 * 1024 * 10,
		},
	})
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		c.log.Error(strings.Join(ve.Log, "\n"))
	}
	if err != nil {
		return err
	}
	c.egressProg = objs.bpfPrograms.Egress
	c.ingressProg = objs.bpfPrograms.CapturePackets
	return nil
}

func (c *Controller) attach() error {
	var err error
	c.ingressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    c.cgroupfs,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.ingressProg,
	})
	if err != nil {
		return err
	}

	c.egressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    c.cgroupfs,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.egressProg,
	})
	return err
}

func (c *Controller) runDNSReader() {
	c.log.Infof("starting ringbuf reader")
	rd, err := ringbuf.NewReader(c.eventsMap)
	if err != nil {
		c.log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err == ringbuf.ErrClosed {
			c.log.Fatalf("closed event ringbuf reader, stop reconciling allow list: %s", err.Error())
			return
		} else if err != nil {
			c.log.Error(err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			c.log.Errorf("parsing ringbuf event: %s", err)
			continue
		}

		var msg dns.Msg
		err = msg.Unpack(event.Pkt[:event.Len])
		if err != nil {
			dnsParseError.WithLabelValues(strconv.FormatInt(int64(event.Key), 10)).Inc()
			c.log.Errorf("unable to unpack dns: ev: len=%d key=%s %#v %s", event.Len, keyToIP(event.Key), event.Pkt, err)
			continue
		}

		var hostnames []string
		var ips []net.IP
		for _, a := range msg.Answer {
			// all hostnames are captured and passed to tryAllowAccess
			// which will check whether or not this one is allowed
			cname, ok := a.(*dns.CNAME)
			if ok {
				hostnames = append(hostnames, cname.Header().Name)
				continue
			}
			// for now, only support ipv4
			arec, ok := a.(*dns.A)
			if !ok {
				continue
			}
			v4 := arec.A.To4()
			hostnames = append(hostnames, arec.Header().Name)
			ips = append(ips, v4)
		}
		c.dnsCache.SetMany(hostnames, ips)
		err = c.tryAllowAddress(hostnames, ips, event.Key)
		if err != nil {
			c.log.Errorf("unable to update dns record state: %s", err.Error())
		}
	}
}

func (c *Controller) tryAllowAddress(hosts []string, ips []net.IP, key uint32) error {
	if len(hosts) == 0 || len(ips) == 0 {
		return nil
	}
	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()

	// see if a host matches
	var found bool
	for _, host := range hosts {

		// check if host index contains the hostname that has been requested
		addrIdx, ok := c.hostIdx[host]
		if !ok {
			continue
		}
		// check if this pod is supposed to access this hostname
		_, ok = addrIdx[key]
		if ok {
			found = true
		}
	}

	if !found {
		for _, host := range hosts {
			lookupForbiddenHostname.WithLabelValues(strconv.FormatUint(uint64(key), 10), host).Inc()
		}
		return fmt.Errorf("key=%s tried to access unallowed host: %s", keyToIP(key), hosts[0])
	}

	for _, addr := range ips {
		resolvedAddr := binary.LittleEndian.Uint32(addr)
		c.log.Infof("unblocking resolved addr: daddr=%s key=%s", keyToIP(resolvedAddr), keyToIP(key))

		var innerID ebpf.MapID
		err := c.egressConfig.Lookup(key, &innerID)
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
	}

	return nil
}

func (c *Controller) updateConfig() error {
	addrIdx, hostIdx, err := c.indicesFromEgressConfig()
	if err != nil {
		return err
	}

	updateStaticIPs := func(innerID ebpf.MapID, key uint32, staticAddrs map[uint32]uint32) {
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Errorf("unable to access inner map: %s", err.Error())
			return
		}
		defer m.Close()

		// allow static IPs
		for addr, setting := range staticAddrs {
			err = m.Put(addr, setting)
			if err != nil {
				c.log.Errorf("unable to put static ip key=%d addr=%d: %s", key, addr, err)
			}
		}
	}

	// set up outer map and store IPs
	for key, staticAddrs := range addrIdx {
		var innerID ebpf.MapID
		err = c.egressConfig.Lookup(key, &innerID)
		if err == nil {
			updateStaticIPs(innerID, key, staticAddrs)
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup egress config: %s", err.Error())
			continue
		}

		m, err := ebpf.NewMap(innerPodMap)
		if err != nil {
			c.log.Errorf("unable to create inner map: %s", err.Error())
			continue
		}
		defer m.Close()
		inf, err := m.Info()
		if err != nil {
			c.log.Errorf("unable to get egress config map info: %s", err.Error())
			continue
		}
		var ok bool
		innerID, ok = inf.ID()
		if !ok {
			c.log.Errorf("unable to get egress config map id: %s", err.Error())
			continue
		}
		err = c.egressConfig.Put(key, uint32(m.FD()))
		if err != nil {
			return err
		}
		updateStaticIPs(innerID, key, staticAddrs)
	}

	c.hostIdxmu.Lock()
	//c.cleanupState(c.hostIdx, hostIdx)
	c.reconcileState(addrIdx)
	c.hostIdx = hostIdx
	c.hostIdxmu.Unlock()

	return nil
}

func (c *Controller) dumpMap() {
	c.log.Debug("dumping egress config")
	it := c.egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		c.log.Debugf("egress config key=%s", keyToIP(key))
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warn(err)
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal uint32
		for iit.Next(&innerKey, &innerVal) {
			c.log.Debugf("[%s] %s=>%d", keyToIP(key), keyToIP(innerKey), innerVal)
		}
	}
}

func keyToIP(addr uint32) string {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, addr)
	return net.IP(buf.Bytes()).To4().String()
}

// TODO: revisit and remove
//
//	it shouldn't be needed due to the reconcileState() implementation below
//
// cleans up stale data in BPF maps
// case 1: pod has been removed from this node
// case 2: hostname has been removed and must should be blocked
// old/new map contains hostname => map[podKey]=>allowed state
func (c *Controller) cleanupState(old, new map[string]map[uint32]struct{}) {

	// case 1: cleanup pods that have been removed from this Node.
	// slice of podKeys
	keysToRemove := []uint32{}
	// podKey => addrs to remove
	hostsToRemove := map[uint32][]uint32{}

	// we lookup the ip addresses and cache it here
	// map hostname => upstream addrs
	hostCache := map[string][]uint32{}
	for host, oldPods := range old {
		if new[host] == nil {
			// hostname has been removed
			// store upstream addrs so we can remove them further below
			for oldPod := range oldPods {
				if hostsToRemove[oldPod] == nil {
					hostsToRemove[oldPod] = []uint32{}
				}
				if hostCache[host] == nil {
					addrs, err := net.LookupIP(host)
					if err != nil {
						c.log.Error("unable to lookup host: %s", err)
						continue
					}
					hostCache[host] = []uint32{}
					for _, addr := range addrs {
						v4 := addr.To4()
						if v4 == nil {
							continue
						}
						hostCache[host] = append(hostCache[host], binary.LittleEndian.Uint32(v4))
					}
				}
				hostsToRemove[oldPod] = hostCache[host]
			}
			continue
		}
		// iterate over old pods
		// if they are not in `new` they must be removed
		for oldPod := range oldPods {
			_, ok := new[host][oldPod]
			if !ok {
				keysToRemove = append(keysToRemove, oldPod)
			}
		}
	}

	for _, key := range keysToRemove {
		c.log.Debugf("deleting key from egressConfig: %s", keyToIP(key))
		err := c.egressConfig.Delete(key)
		if err != nil && err != ebpf.ErrKeyNotExist {
			c.log.Warnf("could not delete key %s: %v", keyToIP(key), err)
		}
	}

	// case 2: delete upstream addresses from maps
	//         to block outgoing connections
	for key, addrs := range hostsToRemove {
		var innerID ebpf.MapID
		err := c.egressConfig.Lookup(key, &innerID)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			c.log.Warn("could not lookup pod key=%s: %s", keyToIP(key), err)
			continue
		}
		innerMap, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to create map from inner id=%d key=%s: %s", innerID, keyToIP(key), err)
			continue
		}
		for _, addr := range addrs {
			c.log.Debugf("deleting addr: %s", keyToIP(addr))
			err = innerMap.Delete(addr)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Warnf("unable to cleanup inner ip key=%s addr=%s err=%s", keyToIP(key), keyToIP(addr), err.Error())
				continue
			}
		}
	}

}

// reconcileState sweeps through all key/value pairs in egressConfig
// and removes orphaned pods
func (c *Controller) reconcileState(addrIdx map[uint32]map[uint32]uint32) {
	it := c.egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := addrIdx[key]; !ok {
			c.log.Debugf("reconciling egress, removing key=%s", keyToIP(key))
			err := c.egressConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Warnf("unable to reconcile pod key=%s %s", keyToIP(key), err.Error())
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to get map from inner id key=%s id=%d: %s", keyToIP(key), innerID, err.Error())
			continue
		}
		iit := m.Iterate()
		var destAddr uint32
		var allowed uint32
		for iit.Next(&destAddr, &allowed) {
			// case: state exists in bpf map where it shouldn't
			if _, ok := addrIdx[key][destAddr]; !ok {
				c.log.Debugf("reconciling egress ips, removing key=%s ip=%s", keyToIP(key), keyToIP(destAddr))
				err = m.Delete(destAddr)
				if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
					c.log.Warnf("unable to delete key=%s dest=%s", keyToIP(key), keyToIP(destAddr))
				}
				continue
			}
		}
	}
}

func (c *Controller) indicesFromEgressConfig() (map[uint32]map[uint32]uint32, map[string]map[uint32]struct{}, error) {
	addrIdx := make(map[uint32]map[uint32]uint32)
	hostIdx := make(map[string]map[uint32]struct{})
	var egressList v1alpha1.EgressList
	err := c.client.List(c.ctx, &egressList)
	if err != nil {
		return nil, nil, err
	}
	for _, egress := range egressList.Items {

		// prepare allowed egress ips
		hosts := []string{}
		egressIPs := map[uint32]uint32{}
		for _, rule := range egress.Spec.Rules {
			hosts = append(hosts, rule.Domains...)
			// add static ips
			for _, ip := range rule.IPs {
				key := keyForAddr(net.ParseIP(ip))
				egressIPs[key] = ActionAllow
			}
			// add dynamic ips (without wildcards)
			for _, domain := range rule.Domains {
				addrs := c.dnsCache.Lookup(domain)
				if addrs == nil {
					continue
				}
				for addr := range addrs {
					egressIPs[addr] = ActionAllow
				}
			}
		}

		// add allowed dns servers
		for _, addr := range c.allowedDNS {
			egressIPs[addr] = ActionAllow
		}

		// handle host firewall
		if egress.Spec.PodSelector == nil {
			// TODO: check if node matches selector
			key := keyForAddr(net.ParseIP(c.nodeIP))
			// add known ips to map
			addrIdx[key] = egressIPs
			for _, hostname := range hosts {
				if hostIdx[hostname] == nil {
					hostIdx[hostname] = make(map[uint32]struct{})
				}
				hostIdx[hostname][key] = struct{}{}
			}
			continue
		}

		var podList v1.PodList
		err := c.client.List(c.ctx, &podList,
			client.MatchingLabels(egress.Spec.PodSelector.MatchLabels),
			&client.ListOptions{FieldSelector: fields.ParseSelectorOrDie("spec.nodeName=" + c.nodeName)})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to list pods: %w", err)
		}

		// for every pod: prepare address and hostname indices
		// so we can do a lookup by pod key
		for _, pod := range podList.Items {
			if pod.Status.PodIP == "" {
				continue
			}
			podIP := net.ParseIP(pod.Status.PodIP)
			if podIP == nil {
				c.log.Errorf("unable to parse ip %q", podIP)
				continue
			}
			key := keyForAddr(podIP)
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			addrIdx[key] = egressIPs

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
				mergeKeyMap(addrIdx[key], c.dnsCache.Lookup(hostname))
			}
			c.log.Debugf("got pod %s/%s=>%s => %#v", pod.Namespace, pod.Name, pod.Status.PodIP, addrIdx[key])
		}
	}
	return addrIdx, hostIdx, nil
}

func keyForAddr(addr net.IP) uint32 {
	return binary.LittleEndian.Uint32(addr.To4())
}

// copy keys from source into the dest map
func mergeKeyMap(dest map[uint32]uint32, src map[uint32]struct{}) {
	if src == nil {
		return
	}
	for k := range src {
		dest[k] = ActionAllow
	}
}

func (c *Controller) Close() {
	c.log.Debug("closing bpf resources")
	c.egressProg.Close()
	c.ingressProg.Close()
	c.ingressLink.Close()
	c.egressLink.Close()

	// uncomment to clean up map state
	// c.eventsMap.Unpin()
	// c.egressConfig.Unpin()
	// c.dnsConfig.Unpin()
	// c.metricsMap.Unpin()
	// c.metricsBlockedAddr.Unpin()

	c.eventsMap.Close()
	c.egressConfig.Close()
	c.dnsConfig.Close()
	c.metricsMap.Close()
	c.metricsBlockedAddr.Close()
}
