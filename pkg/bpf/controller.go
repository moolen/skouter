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

	hostIdxmu *sync.RWMutex
	hostIdx   map[string]map[uint32]struct{}

	capturePacketsProg *ebpf.Program
	blockPacketsProg   *ebpf.Program
	podConfigMap       *ebpf.Map
	eventsMap          *ebpf.Map

	ingressLink link.Link
	egressLink  link.Link
}

const (
	// This flag is required for dynamically sized inner maps.
	// Added in linux 5.10.
	BPF_F_INNER_MAP = 0x1000
)

var (
	// Action used by the bpf program
	// needs to be in sync with cgroup_skb.c
	ActionAllow = uint32(1)
	ActionDeny  = uint32(2)

	innerMapSpec = &ebpf.MapSpec{
		Name:      "pod_egress_config",
		Type:      ebpf.Hash,
		KeySize:   4, // 4 bytes for u32
		ValueSize: 4, // 4 bytes for u32

		// BPF_F_INNER_MAP doesn't work with Hash type. Array works fine :shrug:
		//Flags:      BPF_F_INNER_MAP,
		MaxEntries: 256,
	}
)

type DefaultAction uint8

const (
	DefaultActionAllow DefaultAction = 1
	DefaultActionDeny  DefaultAction = 2
)

func New(ctx context.Context, client client.Client, cgroupfs, bpffs string, log logrus.FieldLogger, updateChan chan struct{}) (*Controller, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	ctrl := &Controller{
		ctx:        ctx,
		log:        log,
		updateChan: updateChan,
		client:     client,
		cgroupfs:   cgroupfs,
		bpffs:      bpffs,

		hostIdxmu: &sync.RWMutex{},
		hostIdx:   make(map[string]map[uint32]struct{}),
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
	go c.reconileAllowList()

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
	c.log.Infof("map events pinned: %t", c.eventsMap.IsPinned())

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

	c.eventsMap = objs.bpfMaps.Events
	c.podConfigMap = objs.bpfMaps.PodConfig
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
	c.blockPacketsProg = objs.bpfPrograms.BlockPackets
	c.capturePacketsProg = objs.bpfPrograms.CapturePackets
	return nil
}

func (c *Controller) reconileAllowList() {
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

		// data is in network byte order (big endian)
		podIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(podIP, event.PodAddr)

		var msg dns.Msg
		err = msg.Unpack(event.Pkt[:event.Len])
		if err != nil {
			c.log.Error(err)
			continue
		}

		for _, a := range msg.Answer {
			err = c.updateDNSRecordState(a, podIP, event)
			if err != nil {
				c.log.Errorf("unable to update dns record state: %s", err.Error())
			}
		}
	}
}

func (c *Controller) updateDNSRecordState(a dns.RR, podIP net.IP, event bpfEvent) error {
	// for now, support IPv4/A Records only
	arec, ok := a.(*dns.A)
	if !ok {
		return nil
	}

	c.hostIdxmu.RLock()
	defer c.hostIdxmu.RUnlock()
	addrIdx, ok := c.hostIdx[a.Header().Name]
	if !ok {
		return fmt.Errorf("pod %s tried to access unallowed host: %s", podIP.String(), a.Header().Name)
	}

	c.log.Infof("got DNS A response: %s %s", a.Header().Name, arec.A.String())
	resolvedAddr := binary.LittleEndian.Uint32(arec.A.To4())
	key := binary.LittleEndian.Uint32(podIP.To4()) % 255
	c.log.Infof("unblocking resolved addr: saddr=%d daddr=%d key=%d", event.PodAddr, resolvedAddr, key)

	if _, ok := addrIdx[event.PodAddr]; !ok {
		return fmt.Errorf("could not find source addr=%d in host idx", event.PodAddr)
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

func (c *Controller) attach(path string) error {
	var err error
	c.ingressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: c.capturePacketsProg,
	})
	if err != nil {
		return err
	}

	c.egressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.blockPacketsProg,
	})
	return err
}

func (c *Controller) updateConfig() error {
	podIPMap, hostIdx, err := c.indicesFromEgressConfig()
	if err != nil {
		return err
	}

	// TODO: cleanup old ips/maps once the pods gets deleted

	// set up outer map and store IPs
	for ipStr := range podIPMap {
		var innerID ebpf.MapID
		podIP := net.ParseIP(ipStr)
		if podIP == nil {
			c.log.Errorf("unable to parse ip %q", ipStr)
			continue
		}
		podIP = podIP.To4()
		key := binary.LittleEndian.Uint32(podIP) % 255
		c.log.Debugf("updating config for ip=%s be_addr=%d", ipStr, podIP, key)
		err = c.podConfigMap.Lookup(key, &innerID)
		if err == nil {
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup pod_config id=%s: %s %#v", ipStr, err.Error(), err)
			continue
		}

		m, err := ebpf.NewMap(innerMapSpec)
		if err != nil {
			c.log.Errorf("unable to create inner map ip=%s: %s", ipStr, err.Error())
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
	}

	c.hostIdxmu.Lock()
	c.hostIdx = hostIdx
	c.hostIdxmu.Unlock()

	return nil
}

func (c *Controller) indicesFromEgressConfig() (map[string]uint32, map[string]map[uint32]struct{}, error) {
	ipIdx := make(map[string]uint32)
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
			ipIdx[pod.Status.PodIP] = ActionAllow
			for _, host := range hosts {
				// we need to normalize this to a fqdn
				idx := host
				if !strings.HasSuffix(host, ".") {
					idx += "."
				}
				if hostIdx[idx] == nil {
					hostIdx[idx] = make(map[uint32]struct{})
				}
				podIP := net.ParseIP(pod.Status.PodIP)
				podIPnet := binary.LittleEndian.Uint32(podIP.To4())
				hostIdx[idx][podIPnet] = struct{}{}
			}
		}
	}
	return ipIdx, hostIdx, nil
}

func (c *Controller) Close() {
	c.log.Debug("closing bpf resources")
	c.blockPacketsProg.Close()
	c.capturePacketsProg.Close()
	c.eventsMap.Close()
	c.podConfigMap.Close()
	c.ingressLink.Close()
	c.egressLink.Close()
}
