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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jackpal/gateway"
	"github.com/miekg/dns"
	v1alpha1 "github.com/moolen/skouter/api"
	dnscache "github.com/moolen/skouter/pkg/dns_cache"
	"github.com/moolen/skouter/pkg/util"
	"github.com/moolen/skouter/pkg/wildcard"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event -type cidr_config_val bpf ./c/cgroup_skb.c -- -I./c/headers
type Controller struct {
	ctx        context.Context
	client     client.Client
	log        logrus.FieldLogger
	reg        *prometheus.Registry
	auditMode  bool
	nodeName   string
	nodeIP     string
	updateChan chan struct{}
	cgroupfs   string
	bpffs      string
	gwAddr     uint32
	gwIfAddr   uint32
	allowedDNS []uint32
	dnsCache   *dnscache.Cache
	wcCache    *wildcard.Cache

	hostIdxmu *sync.RWMutex
	// hostIdx is a map: hostname => map[pod-key]=>allowed-state
	hostIdx map[string]map[uint32]struct{}
	ruleIdx map[uint32]map[string]*regexp.Regexp

	ingressProg *ebpf.Program
	egressProg  *ebpf.Program

	egressConfig       *ebpf.Map
	egressCIDRConfig   *ebpf.Map
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

	BPFMountDir = "skouter"

	// inner map must be in sync with cgroup_skb.c
	innerIPMap = &ebpf.MapSpec{
		Name:       "pod_egress_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  4, // 4 bytes for u32
		MaxEntries: 4096,
	}

	// inner cidr must be in sync with cgroup_skb.c
	innerCIDRMap = &ebpf.MapSpec{
		Name:       "pod_egress_cidr_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  8, // 8 bytes for u64 IPv4 + mask
		MaxEntries: 256,
	}
)

func New(
	ctx context.Context,
	client client.Client,
	cgroupfs,
	bpffs,
	nodeName,
	nodeIP,
	cacheStoragePath string,
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

	log.Infof("discovered gateway=%s if=%s", gwAddr.String(), gwIfAddr.String())

	wc := wildcard.New(log, cacheStoragePath)
	wc.Restore()
	go wc.Autosave(ctx, time.Second*15)

	ctrl := &Controller{
		ctx:        ctx,
		log:        log,
		reg:        reg,
		updateChan: updateChan,
		client:     client,
		cgroupfs:   cgroupfs,
		bpffs:      bpffs,
		allowedDNS: dnsAddrs,
		gwAddr:     binary.LittleEndian.Uint32(gwAddr.To4()),
		gwIfAddr:   binary.LittleEndian.Uint32(gwIfAddr.To4()),
		dnsCache:   dnscache.New(log),
		wcCache:    wc,
		nodeName:   nodeName,
		nodeIP:     nodeIP,
		auditMode:  auditMode,
		hostIdxmu:  &sync.RWMutex{},
		hostIdx:    make(map[string]map[uint32]struct{}),
	}

	err = ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}

func (c *Controller) Run() error {
	newMetricsCollector(c.reg, c)

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
		return fmt.Errorf("unable to prewarm: %s", err)
	}

	// finally attach the program to
	err = c.attach()
	if err != nil {
		return fmt.Errorf("unable to attach to cgroup2: %s", err.Error())
	}

	go c.runDNSReader()

	// reconcile the state every 5s to ensure that wildcard cache
	// converges quickly.
	// The problem is writes are happening through the ringbuf
	// while egress/pod reconciliation is happening in a different
	// goroutine.
	// Worst case: if the controller restarts the all wildcard cache data is lost
	// and traffic will be delayed again for ~1s (DNS roundtrip + tcp retry).
	tt := time.NewTicker(time.Second * 5)
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
			c.updateConfig()
		}
	}
}

func (c *Controller) preWarm() error {
	c.log.Infof("starting prewarm")
	// prepare bpf maps
	err := c.updateConfig()
	if err != nil {
		return fmt.Errorf("update config: %s", err)
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
	pinPath := filepath.Join(c.bpffs, BPFMountDir)
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
	c.egressCIDRConfig = objs.bpfMaps.EgressCidrConfig
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
			LogSize: 1024,
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

func (c *Controller) allowedByWildcard(hostnames []string, ips []net.IP, key uint32) (string, bool) {
	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()
	rules := c.ruleIdx[key]
	c.log.Debugf("checking allowed hostnames=%#v ips=%#v rules=%#v", hostnames, ips, rules)
	for _, hostname := range hostnames {
		// hostname has a trailing `.` (FQDN)
		hostname := strings.TrimSuffix(hostname, ".")
		for wildcard, re := range rules {
			if re.MatchString(hostname) {
				return wildcard, true
			}
		}
	}
	return "", false
}

func (c *Controller) tryAllowAddress(hosts []string, ips []net.IP, key uint32) error {
	if len(hosts) == 0 || len(ips) == 0 {
		return nil
	}
	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()

	// see if there is a explicit host match
	var allowedByHost bool
	for _, host := range hosts {
		// check if host index contains the hostname that has been requested
		addrIdx, ok := c.hostIdx[host]
		if !ok {
			continue
		}
		// check if this pod is supposed to access this hostname
		_, ok = addrIdx[key]
		if ok {
			allowedByHost = true
		}
	}

	wildcard, allowedByWildcard := c.allowedByWildcard(hosts, ips, key)
	if allowedByWildcard {
		c.wcCache.Observe(wildcard, hosts, ips)
	}

	if !allowedByHost && !allowedByWildcard {
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
	addrIdx, cidrIdx, hostIdx, ruleIdx, err := c.generateIndices()
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

		m, err := ebpf.NewMap(innerIPMap)
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
			return fmt.Errorf("cannot put egress config key: %s", err)
		}
		updateStaticIPs(innerID, key, staticAddrs)
	}

	updateCIDRs := func(innerID ebpf.MapID, key uint32, cidrMap map[string]*net.IPNet) {
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Errorf("unable to access inner map: %s", err.Error())
			return
		}
		defer m.Close()

		// idx=0 holds the number of cidrs
		numCIDRs := len(cidrMap)
		err = m.Put(uint32(0), uint64(numCIDRs))
		if err != nil {
			c.log.Errorf("unable to store cidr len key=%s, len=%d", util.ToIP(key), numCIDRs)
			return
		}

		// allow CIDRs
		// index 1..256
		for i, cidr := range orderedCIDRMap(cidrMap) {
			idx := i + 1
			err = m.Put(uint32(idx), cidr)
			if err != nil {
				c.log.Errorf("unable to put cidr key=%d cidr=%s: %s", key, util.ToNetMask(cidr.Addr, cidr.Mask), err)
			}
		}
	}

	// set up outer map and store CIDRs
	for key, cidrs := range cidrIdx {
		var innerID ebpf.MapID
		err = c.egressCIDRConfig.Lookup(key, &innerID)
		if err == nil {
			updateCIDRs(innerID, key, cidrs)
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup egress config: %s", err.Error())
			continue
		}

		m, err := ebpf.NewMap(innerCIDRMap)
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
		err = c.egressCIDRConfig.Put(key, uint32(m.FD()))
		if err != nil {
			return fmt.Errorf("cannot put egress cidr config key: %s", err)
		}
		updateCIDRs(innerID, key, cidrs)
	}

	// reconcile bpf maps
	c.wcCache.ReconcileIndex(ruleIdx)
	c.reconcileAddrMap(addrIdx)
	c.reconcileCIDRMap(cidrIdx)

	c.hostIdxmu.Lock()
	c.hostIdx = hostIdx
	c.ruleIdx = ruleIdx
	c.hostIdxmu.Unlock()

	return nil
}

func keyToIP(addr uint32) string {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, addr)
	return net.IP(buf.Bytes()).To4().String()
}

// reconcileAddrMap sweeps through all key/value pairs in egressConfig
// and removes orphaned pods
func (c *Controller) reconcileAddrMap(addrIdx map[uint32]map[uint32]uint32) {
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

				// make sure this is not a wildcard
				if c.wcCache.HasAddr(destAddr) {
					continue
				}

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

// reconcileCIDRMap sweeps through all key/value paris in egressCIDRConfig
// and removes orphaned pods
func (c *Controller) reconcileCIDRMap(cidrIdx map[uint32]map[string]*net.IPNet) {
	it := c.egressCIDRConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := cidrIdx[key]; !ok {
			c.log.Debugf("reconciling egress cidr, removing key=%s", keyToIP(key))
			err := c.egressCIDRConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Warnf("unable to reconcile pod cidr key=%s %s", keyToIP(key), err.Error())
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to get cidr map from inner id key=%s id=%d: %s", keyToIP(key), innerID, err.Error())
			continue
		}
		iit := m.Iterate()
		var i uint32
		var cidr bpfCidrConfigVal

		for iit.Next(&i, &cidr) {
			if i != 0 && // idx=0 contains size
				i >= uint32(len(cidrIdx[key])+1) && // we might have stale values at the end
				cidr.Addr != 0 &&
				cidr.Mask != 0 {
				c.log.Debugf("reconciling egress CIDRs, removing key=%s cidr=%s", keyToIP(key), util.ToNetMask(cidr.Addr, cidr.Mask).String())
				err = m.Delete(i)
				if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
					c.log.Warnf("unable to delete key=%s cidr=%s", keyToIP(key), util.ToNetMask(cidr.Addr, cidr.Mask).String())
				}
				continue
			}
		}
	}
}

func orderedCIDRMap(cidr map[string]*net.IPNet) []bpfCidrConfigVal {
	keys := []string{}
	for k := range cidr {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []bpfCidrConfigVal{}
	for _, key := range keys {
		val := cidr[key]
		if val.IP.IsUnspecified() || bytes.Equal(val.Mask, []byte{0, 0, 0, 0}) {
			continue
		}
		bpfVal := bpfCidrConfigVal{
			Addr: util.IPToUint(val.IP),
			Mask: util.MaskToUint(val.Mask),
		}
		out = append(out, bpfVal)
	}
	return out
}

func (c *Controller) generateIndices() (map[uint32]map[uint32]uint32, map[uint32]map[string]*net.IPNet, map[string]map[uint32]struct{}, map[uint32]map[string]*regexp.Regexp, error) {
	addrIdx := make(map[uint32]map[uint32]uint32)
	cidrIdx := make(map[uint32]map[string]*net.IPNet)
	hostIdx := make(map[string]map[uint32]struct{})
	addrRuleIdx := make(map[uint32]map[string]*regexp.Regexp)
	var egressList v1alpha1.EgressList
	err := c.client.List(c.ctx, &egressList)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, egress := range egressList.Items {

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

			for _, cidr := range rule.CIDRs {
				_, net, err := net.ParseCIDR(cidr)
				if err != nil {
					c.log.Errorf("unable to parse cidr: %#v", err)
					continue
				}
				egressCIDRs[net.String()] = net
			}

			for _, wildcard := range rule.Wildcards {
				re, err := regexp.Compile(wildcard)
				if err != nil {
					c.log.Error(err)
					continue
				}
				egressRegexs[wildcard] = re
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
			var node v1.Node
			err := c.client.Get(context.Background(), types.NamespacedName{Name: c.nodeName}, &node)
			if err != nil {
				continue
			}
			sel := labels.SelectorFromValidatedSet(labels.Set(egress.Spec.NodeSelector.MatchLabels))
			if !sel.Matches(labels.Set(node.ObjectMeta.Labels)) {
				c.log.Debugf("egress %s node selector %#v doesn't match labels of this node %s: %#v",
					&egress.ObjectMeta.Name, egress.Spec.NodeSelector.MatchLabels, c.nodeName, node.ObjectMeta.Labels)
				continue
			}

			key := keyForAddr(net.ParseIP(c.nodeIP))
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if addrRuleIdx[key] == nil {
				addrRuleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// host firewall needs to be allowed to send traffic to
			// the default gateway and to localhost
			egressIPs[c.gwAddr] = ActionAllow
			egressIPs[c.gwIfAddr] = ActionAllow

			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(addrRuleIdx[key], egressRegexs)

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
			return nil, nil, nil, nil, fmt.Errorf("unable to list pods: %w", err)
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
				c.log.Errorf("unable to parse ip %q", podIP)
				continue
			}
			key := keyForAddr(podIP)
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if addrRuleIdx[key] == nil {
				addrRuleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(addrRuleIdx[key], egressRegexs)

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
			c.log.Debugf("got pod %s/%s=>%s => %#v", pod.Namespace, pod.Name, pod.Status.PodIP, addrIdx[key])
		}
	}
	return addrIdx, cidrIdx, hostIdx, addrRuleIdx, nil
}

func keyForAddr(addr net.IP) uint32 {
	return binary.LittleEndian.Uint32(addr.To4())
}

// copy keys from source into the dest map
func mergeNetMap(dest map[string]*net.IPNet, src map[string]*net.IPNet) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

func mergeRegexpMap(dest map[string]*regexp.Regexp, src map[string]*regexp.Regexp) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeKeyMap(dest map[uint32]uint32, src map[uint32]uint32) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeHostMap(dest map[uint32]uint32, src map[uint32]struct{}) {
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

	// Flush wildcard cache to disk
	// so it can be restored
	err := c.wcCache.Save()
	if err != nil {
		c.log.Error(err)
	}

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
