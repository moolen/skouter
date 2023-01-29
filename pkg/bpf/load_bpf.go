package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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
		if err := spec.RewriteConstants(map[string]interface{}{
			"audit_mode": uint32(1),
		}); err != nil {
			return err
		}
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
