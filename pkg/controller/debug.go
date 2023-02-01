package bpf

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/cache/regex"
	"github.com/moolen/skouter/pkg/util"
	"github.com/sirupsen/logrus"
)

func DumpConfig(log logrus.FieldLogger, bpffs, storagePath string) error {
	log.Debugf("dumping regex cache from %s", storagePath)
	reCache := regex.New(log, storagePath)
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

	log.Debugf("dumping egress config from %s", egressConfigPath)
	it := egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		log.Debugf("egress config key=%s", keyToIP(key))
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			log.Warn(err)
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal uint32
		for iit.Next(&innerKey, &innerVal) {
			log.Debugf("[%s] %s=>%d", keyToIP(key), keyToIP(innerKey), innerVal)
		}
	}

	log.Debugf("dumping egress cidr config from %s", egressCidrConfigPath)
	it = egressCIDRConfig.Iterate()
	for it.Next(&key, &innerID) {
		log.Debugf("egress cidr config key=%s", keyToIP(key))
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			log.Warn(err)
			continue
		}
		iit := m.Iterate()
		var innerKey uint32
		var innerVal bpf.CidrConfigVal
		for iit.Next(&innerKey, &innerVal) {
			if innerVal.Addr != 0 && innerVal.Mask != 0 {
				log.Debugf("[%s] %d=>%#v", keyToIP(key), innerKey, util.ToNetMask(innerVal.Addr, innerVal.Mask))
			}
		}
	}
	return nil
}
