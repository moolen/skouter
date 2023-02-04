package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type CidrConfigVal bpfCidrConfigVal

type Event bpfEvent

type LoadedCollection struct {
	EgressProg *ebpf.Program
	EgressLink link.Link

	EgressConfig       *EgressConfig
	EgressCIDRConfig   *EgressCIDRConfig
	DNSConfig          *ebpf.Map
	MetricsMap         *ebpf.Map
	MetricsBlockedAddr *ebpf.Map
	EventsMap          *ebpf.Map
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event -type cidr_config_val bpf ./c/cgroup_skb.c -- -I./c/headers
func Load(pinPath string, auditMode bool) (*LoadedCollection, error) {
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	if auditMode {
		if err := spec.RewriteConstants(map[string]interface{}{
			"audit_mode": uint32(1),
		}); err != nil {
			return nil, err
		}
	}
	err = spec.LoadAndAssign(&objs.bpfMaps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	})
	if err != nil {
		return nil, err
	}
	err = spec.LoadAndAssign(&objs.bpfPrograms, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ebpf.ProgramOptions{
			LogSize: 1024,
		},
	})
	if err != nil {
		return nil, err
	}
	return &LoadedCollection{
		EgressProg: objs.bpfPrograms.Egress,

		EgressConfig:       &EgressConfig{objs.bpfMaps.EgressConfig},
		EgressCIDRConfig:   &EgressCIDRConfig{objs.bpfMaps.EgressCidrConfig},
		DNSConfig:          objs.bpfMaps.DnsConfig,
		MetricsMap:         objs.bpfMaps.Metrics,
		MetricsBlockedAddr: objs.bpfMaps.MetricsBlockedAddr,
		EventsMap:          objs.bpfMaps.Events,
	}, nil
}

func (coll *LoadedCollection) Attach(cgroupfs string) error {
	var err error
	coll.EgressLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupfs,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: coll.EgressProg,
	})
	return err
}

func (coll *LoadedCollection) Close() error {
	coll.EgressProg.Close()
	coll.EgressLink.Close()

	coll.EventsMap.Close()
	coll.EgressConfig.Close()
	coll.EgressCIDRConfig.Close()
	coll.DNSConfig.Close()
	coll.MetricsMap.Close()
	coll.MetricsBlockedAddr.Close()
	return nil
}
