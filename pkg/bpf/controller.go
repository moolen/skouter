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
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
	v1alpha1 "github.com/moolen/skouter/api"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf ./c/cgroup_skb.c -- -I./c/headers
type Controller struct {
	ctx        context.Context
	client     client.Client
	log        logrus.FieldLogger
	updateChan chan struct{}
	cgroupfs   string
	bpffs      string
	allowedDNS uint32

	hostIdxmu *sync.RWMutex
	// hostIdx is a map: hostname => map[pod-key]=>allowed-state
	hostIdx map[string]map[uint32]struct{}

	captureIngressProg *ebpf.Program
	egressProg         *ebpf.Program
	podConfigMap       *ebpf.Map
	eventsMap          *ebpf.Map

	ingressLink link.Link
	egressLink  link.Link
}

var (
	// Action used by the bpf program
	// needs to be in sync with cgroup_skb.c
	// TODO: pull these settings from bytecode so there's no need to sync
	ActionAllow = uint32(1)
	ActionDeny  = uint32(2)
	ActionAudit = uint32(3)

	innerPodMap = &ebpf.MapSpec{
		Name:       "pod_egress_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  4, // 4 bytes for u32
		MaxEntries: 256,
	}
)

func New(ctx context.Context, client client.Client, cgroupfs, bpffs, allowedDNS string, log logrus.FieldLogger, updateChan chan struct{}) (*Controller, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	dnsAddr := net.ParseIP(allowedDNS)
	if dnsAddr == nil {
		return nil, fmt.Errorf("could not parse dns addr")
	}
	allowedDnsAddr := binary.LittleEndian.Uint32(dnsAddr.To4())

	ctrl := &Controller{
		ctx:        ctx,
		log:        log,
		updateChan: updateChan,
		client:     client,
		cgroupfs:   cgroupfs,
		bpffs:      bpffs,
		allowedDNS: allowedDnsAddr,
		hostIdxmu:  &sync.RWMutex{},
		hostIdx:    make(map[string]map[uint32]struct{}),
	}

	err := ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

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

	go c.processDNSQueries()

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case <-c.updateChan:
			err := c.updateConfig()
			if err != nil {
				c.log.Error(err)
			}
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

	cache := make(map[string][]net.IP)

	for host, podKeys := range c.hostIdx {
		var addrs []net.IP
		var err error
		if cache[host] != nil {
			addrs = cache[host]
		} else {
			c.log.Debugf("prewarm: lookup %q", host)
			addrs, err = net.LookupIP(host)
			if err != nil {
				return err
			}
			cache[host] = addrs
		}
		for _, addr := range addrs {
			hostAddr := addr.To4()
			if hostAddr == nil {
				continue
			}
			for podKey := range podKeys {
				c.tryAllowAddress(host, hostAddr, podKey)
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

	c.log.Infof("map pod_config pinned: %t", c.podConfigMap.IsPinned())

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

	c.podConfigMap = objs.bpfMaps.PodConfig
	c.eventsMap = objs.bpfMaps.Events

	return nil
}

func (c *Controller) loadBPFProgs(pinPath string) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	objs := bpfObjects{}
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
	c.captureIngressProg = objs.bpfPrograms.CapturePackets
	return nil
}

func (c *Controller) attach() error {
	var err error
	c.ingressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    c.cgroupfs,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.captureIngressProg,
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

func (c *Controller) processDNSQueries() {
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
			c.log.Error(err)
			continue
		}

		for _, a := range msg.Answer {
			// for now, only support ipv4
			arec, ok := a.(*dns.A)
			if !ok {
				continue
			}
			v4 := arec.A.To4()
			err = c.tryAllowAddress(arec.Header().Name, v4, event.PodKey)
			if err != nil {
				c.log.Errorf("unable to update dns record state: %s", err.Error())
			}
		}
	}
}

func (c *Controller) tryAllowAddress(host string, addr net.IP, key uint32) error {
	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()
	addrIdx, ok := c.hostIdx[host]
	if !ok {
		return fmt.Errorf("pod %d tried to access unallowed host: %s", key, host)
	}

	c.log.Debugf("got DNS A response: %s %s", host, addr.String())
	resolvedAddr := binary.LittleEndian.Uint32(addr)
	c.log.Infof("unblocking resolved addr: daddr=%d key=%d", resolvedAddr, key)

	if _, ok := addrIdx[key]; !ok {
		return fmt.Errorf("could not find source key=%d in host idx", key)
	}

	var innerID ebpf.MapID
	err := c.podConfigMap.Lookup(key, &innerID)
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
	podIPMap, hostIdx, err := c.indicesFromEgressConfig()
	if err != nil {
		return err
	}

	// set up outer map and store IPs
	for key := range podIPMap {
		var innerID ebpf.MapID
		err = c.podConfigMap.Lookup(key, &innerID)
		if err == nil {
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup pod_config: %s", err.Error())
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
			c.log.Errorf("unable to get pod_config map info: %s", err.Error())
			continue
		}
		var ok bool
		innerID, ok = inf.ID()
		if !ok {
			c.log.Errorf("unable to get pod_config map id: %s", err.Error())
			continue
		}
		err = c.podConfigMap.Update(key, uint32(m.FD()), ebpf.UpdateAny)
		if err != nil {
			c.log.Errorf("unable to put inner map id %d into outer map: %s", innerID, err.Error())
			continue
		}

		// allow pod to access DNS Server
		c.log.Debugf("setting allowed dns server addr=%d for key=%d", c.allowedDNS, key)
		err = m.Update(c.allowedDNS, ActionAllow, ebpf.UpdateAny)
		if err != nil {
			c.log.Errorf("unable to set upstream DNS server address")
		}
	}

	c.hostIdxmu.Lock()
	c.cleanupState(c.hostIdx, hostIdx)
	c.hostIdx = hostIdx
	c.hostIdxmu.Unlock()

	return nil
}

// cleans up stale data in BPF maps
// case 1: pod has been removed from this node
// case 2: hostname has been removed and must should be blocked
// old/new map contains hostname => map[podKey]=>allowed state
func (c *Controller) cleanupState(old, new map[string]map[uint32]struct{}) {

	// case 1: cleanup pods that have been removed from this Node.
	// slice of podKeys
	podsToRemove := []uint32{}
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
				podsToRemove = append(podsToRemove, oldPod)
			}
		}
	}

	for _, podKey := range podsToRemove {
		c.log.Debugf("deleting key: %d", podKey)
		err := c.podConfigMap.Delete(podKey)
		if err != nil && err != ebpf.ErrKeyNotExist {
			c.log.Warnf("could not delete key %d: %v", podKey, err)
		}
	}

	// case 2: delete upstream addresses from maps
	//         to block outgoing connections
	for podKey, addrs := range hostsToRemove {
		var innerID ebpf.MapID
		err := c.podConfigMap.Lookup(podKey, &innerID)
		if err != nil {
			c.log.Warn("could not lookup pod key: %s", err)
			continue
		}
		innerMap, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to create map from inner id: %s", err)
			continue
		}
		for _, addr := range addrs {
			err = innerMap.Delete(addr)
			if err != nil && err != ebpf.ErrKeyNotExist {
				c.log.Warnf("unable to cleanup inner ip key=%d addr=%d err=%#v", podKey, addr, err)
				continue
			}
		}
	}
}

func (c *Controller) indicesFromEgressConfig() (map[uint32]uint32, map[string]map[uint32]struct{}, error) {
	ipIdx := make(map[uint32]uint32)
	hostIdx := make(map[string]map[uint32]struct{})
	var egressList v1alpha1.EgressList
	err := c.client.List(c.ctx, &egressList)
	if err != nil {
		return nil, nil, err
	}
	for _, egress := range egressList.Items {
		hosts := []string{}
		for _, rule := range egress.Spec.Rules {
			hosts = append(hosts, rule.Domains...)
		}

		var podList v1.PodList
		err := c.client.List(c.ctx, &podList, client.MatchingLabels(egress.Spec.PodSelector.MatchLabels))
		if err != nil {
			return nil, nil, err
		}
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
			ipIdx[key] = ActionAllow
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
			}
		}
	}
	return ipIdx, hostIdx, nil
}

func keyForAddr(addr net.IP) uint32 {
	return binary.LittleEndian.Uint32(addr.To4()) % 255
}

func (c *Controller) Close() {
	c.log.Debug("closing bpf resources")
	c.egressProg.Close()
	c.captureIngressProg.Close()

	c.podConfigMap.Close()

	c.ingressLink.Close()
	c.egressLink.Close()
}
