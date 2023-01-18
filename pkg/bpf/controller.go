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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event -type host_key_t bpf ./c/cgroup_skb.c -- -I./c/headers
type Controller struct {
	ctx                context.Context
	client             client.Client
	log                logrus.FieldLogger
	updateChan         chan struct{}
	cgroupfs           string
	bpffs              string
	allowedDNS         uint32
	userspaceDNSParser bool

	hostIdxmu *sync.RWMutex
	hostIdx   map[string]map[uint32]struct{}

	ingressProg        *ebpf.Program
	captureIngressProg *ebpf.Program
	egressProg         *ebpf.Program
	podConfigMap       *ebpf.Map
	hostConfigMap      *ebpf.Map
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

	innerHostMap = &ebpf.MapSpec{
		Name:       "host_egress_config",
		Type:       ebpf.Hash,
		KeySize:    64, // 64 bytes for hostname
		ValueSize:  4,  // 4 bytes for u32
		MaxEntries: 256,
	}
)

func New(ctx context.Context, client client.Client, cgroupfs, bpffs, allowedDNS string, userspaceDNSParser bool, log logrus.FieldLogger, updateChan chan struct{}) (*Controller, error) {
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
		ctx:                ctx,
		log:                log,
		updateChan:         updateChan,
		client:             client,
		cgroupfs:           cgroupfs,
		bpffs:              bpffs,
		allowedDNS:         allowedDnsAddr,
		userspaceDNSParser: userspaceDNSParser,
		hostIdxmu:          &sync.RWMutex{},
		hostIdx:            make(map[string]map[uint32]struct{}),
	}

	err := ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	err = ctrl.attach(cgroupfs)
	if err != nil {
		return nil, fmt.Errorf("unable to attach to cgroup2: %s", err.Error())
	}

	return ctrl, nil
}

func (c *Controller) Run() {
	go c.reconcileAllowList()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.updateChan:
			err := c.updateConfig()
			if err != nil {
				c.log.Error(err)
			}
		}
	}
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
	c.log.Infof("map host_config pinned: %t", c.hostConfigMap.IsPinned())

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
	c.hostConfigMap = objs.bpfMaps.HostConfig
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
	c.ingressProg = objs.bpfPrograms.Ingress
	c.captureIngressProg = objs.bpfPrograms.CapturePackets
	return nil
}

func (c *Controller) attach(path string) error {
	var err error
	desiredProg := c.ingressProg
	if c.userspaceDNSParser {
		desiredProg = c.captureIngressProg
	}
	c.ingressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: desiredProg,
	})
	if err != nil {
		return err
	}

	c.egressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.egressProg,
	})
	return err
}

func (c *Controller) reconcileAllowList() {
	c.log.Infof("starting ringbuf event reader: %#v", c.eventsMap)
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
			err = c.updateDNSRecordState(a, event.PodKey, event)
			if err != nil {
				c.log.Errorf("unable to update dns record state: %s", err.Error())
			}
		}
	}
}

func (c *Controller) updateDNSRecordState(a dns.RR, key uint32, event bpfEvent) error {
	// for now, support IPv4/A Records only
	arec, ok := a.(*dns.A)
	if !ok {
		return nil
	}

	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()
	addrIdx, ok := c.hostIdx[a.Header().Name]
	if !ok {
		return fmt.Errorf("pod %d tried to access unallowed host: %s", key, a.Header().Name)
	}

	c.log.Infof("got DNS A response: %s %s", a.Header().Name, arec.A.String())
	resolvedAddr := binary.LittleEndian.Uint32(arec.A.To4())
	c.log.Infof("unblocking resolved addr: daddr=%d key=%d", event.PodKey, resolvedAddr, key)

	if _, ok := addrIdx[event.PodKey]; !ok {
		return fmt.Errorf("could not find source key=%d in host idx", event.PodKey)
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

	// TODO: cleanup old ips/maps once the pods gets deleted

	// set up outer map and store IPs
	for key := range podIPMap {
		var innerID ebpf.MapID
		c.log.Debugf("updating config for key=%d", key)
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

	updateHostname := func(id ebpf.MapID, hostname string) {
		one := uint32(1)
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			c.log.Error(err)
			return
		}
		err = m.Update(bpfHostKeyT{
			Hostname: cHostname(hostname),
		}, &one, ebpf.UpdateAny)
		if err != nil {
			c.log.Error("unable to set hostname in inner map: %s", err.Error())
		}
	}

	// setup nested maps
	for hostname, podIdx := range hostIdx {
		for key := range podIdx {
			var innerID ebpf.MapID
			c.log.Debugf("updating host config for key=%d", key)
			err = c.hostConfigMap.Lookup(key, &innerID)
			if err == nil {
				c.log.Infof("[%d]=>[%s]", key, hostname)
				updateHostname(innerID, hostname)
				continue
			}
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Errorf("unable to lookup host_config: %s", err.Error())
				continue
			}

			m, err := ebpf.NewMap(innerHostMap)
			if err != nil {
				c.log.Errorf("unable to create host inner map: %s", err.Error())
				continue
			}
			defer m.Close()
			inf, err := m.Info()
			if err != nil {
				c.log.Errorf("unable to get host_config map info: %s", err.Error())
				continue
			}
			var ok bool
			innerID, ok = inf.ID()
			if !ok {
				c.log.Errorf("unable to get host_config map id: %s", err.Error())
				continue
			}
			err = c.hostConfigMap.Update(key, uint32(m.FD()), ebpf.UpdateAny)
			if err != nil {
				c.log.Errorf("host: unable to put inner map id %d into outer map: %s", innerID, err.Error())
				continue
			}
			c.log.Infof("[%d]=>[%s]", key, hostname)
			updateHostname(innerID, hostname)
		}
	}

	c.hostIdxmu.Lock()
	c.hostIdx = hostIdx
	c.hostIdxmu.Unlock()

	return nil
}

func cHostname(hostname string) [64]uint8 {
	var arr [64]uint8
	for i := 0; i < len(hostname); i++ {
		arr[i] = uint8(hostname[i])
	}
	return arr
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
			podIP = podIP.To4()
			key := binary.LittleEndian.Uint32(podIP) % 255
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

func (c *Controller) Close() {
	c.log.Debug("closing bpf resources")
	c.egressProg.Close()
	c.ingressProg.Close()

	c.podConfigMap.Close()
	c.hostConfigMap.Close()

	c.ingressLink.Close()
	c.egressLink.Close()
}
