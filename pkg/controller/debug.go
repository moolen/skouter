package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/moolen/skouter/pkg/bpf"
	dnscache "github.com/moolen/skouter/pkg/cache/dns"
	"github.com/moolen/skouter/pkg/cache/fqdn"
	"github.com/moolen/skouter/pkg/indices"
	"github.com/moolen/skouter/pkg/util"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func DumpConfig(bpffs, storagePath string, cfg *rest.Config, nodeName, nodeIP string, allowedDNS []uint32) error {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	reCache := fqdn.New(storagePath)
	reCache.Restore()
	reCache.DumpMap(t)
	t.AppendSeparator()

	egressConfigPath := filepath.Join(bpffs, BPFMountDir, "egress_config")
	egressCidrConfigPath := filepath.Join(bpffs, BPFMountDir, "egress_cidr_config")

	egressConfig, err := ebpf.LoadPinnedMap(egressConfigPath, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		return fmt.Errorf("unable to load egress config: %w", err)
	}

	egressCIDRConfig, err := ebpf.LoadPinnedMap(egressCidrConfigPath, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		return fmt.Errorf("unable to load egress cidr config: %w", err)
	}

	t.AppendRow(table.Row{"egress IP config"})
	t.AppendSeparator()
	it := egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		t.AppendRow(table.Row{"subject-ip", "egress-ip"})
		t.AppendSeparator()
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			logger.Error(err, "could not create map from inner id")
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal uint32
		for iit.Next(&innerKey, &innerVal) {
			t.AppendRow(table.Row{keyToIP(key), keyToIP(innerKey)})
		}
		t.AppendSeparator()

	}

	t.AppendRow(table.Row{"egress CIDR config"})
	t.AppendSeparator()
	t.AppendRow(table.Row{"subject-ip", "cidr"})
	t.AppendSeparator()
	it = egressCIDRConfig.Iterate()
	for it.Next(&key, &innerID) {
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			logger.Error(err, "unable to create bpf map from id", "id", innerID)
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal bpf.CidrConfigVal
		for iit.Next(&innerKey, &innerVal) {
			if innerVal.Addr != 0 && innerVal.Mask != 0 {
				t.AppendRow(table.Row{keyToIP(key), util.ToNetMask(innerVal.Addr, innerVal.Mask).String()})
			}
		}
	}
	t.AppendSeparator()
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}

	addrIdx, cidrIdx, hostIdx, ruleIdx, err := indices.Generate(context.Background(), dc, kc, dnscache.New(), allowedDNS, nodeIP, nodeName, 0, 0)
	if err != nil {
		return err
	}

	t.AppendRow(table.Row{"address idx"})
	t.AppendSeparator()
	for addr, v := range addrIdx {
		t.AppendRow(table.Row{addr, v})
	}

	t.AppendSeparator()
	t.AppendRow(table.Row{"cidr idx"})
	t.AppendSeparator()
	for addr, v := range cidrIdx {
		t.AppendRow(table.Row{util.ToIP(addr), v})
	}

	t.AppendSeparator()
	t.AppendRow(table.Row{"hostIdx idx"})
	t.AppendSeparator()
	for addr, v := range hostIdx {
		t.AppendRow(table.Row{addr, v})
	}

	t.AppendSeparator()
	t.AppendRow(table.Row{"ruleIdx idx"})
	t.AppendSeparator()
	for addr, v := range ruleIdx {
		t.AppendRow(table.Row{util.ToIP(addr), v})
	}

	t.Render()
	return nil
}
