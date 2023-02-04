package controller

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/cache/fqdn"
	"github.com/moolen/skouter/pkg/util"
)

func DumpConfig(bpffs, storagePath string) error {
	logger.Info("dumping regex cache", "path", storagePath)
	reCache := fqdn.New(storagePath)
	reCache.Restore()
	reCache.DumpMap()

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

	logger.Info("dumping egress config from", "path", egressConfigPath)
	it := egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		logger.Info("egress config", "key", keyToIP(key))
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			logger.Error(err, "could not create map from inner id")
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal uint32
		for iit.Next(&innerKey, &innerVal) {
			logger.Info("", "key", keyToIP(key), "inner-key", keyToIP(innerKey), "val", innerVal)
		}
	}

	logger.Info("dumping egress cidr config from", "path", egressCidrConfigPath)
	it = egressCIDRConfig.Iterate()
	for it.Next(&key, &innerID) {
		logger.Info("egress cidr config key=%s", keyToIP(key))
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
				logger.Info("", "key", keyToIP(key), "inner-key", innerKey, "val", util.ToNetMask(innerVal.Addr, innerVal.Mask))
			}
		}
	}
	return nil
}
