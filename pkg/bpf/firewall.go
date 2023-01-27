package bpf

import "github.com/sirupsen/logrus"

const (
	MaxCIDREntries = 255
)

// FirewallConfig mirrors eBPF map state of the EgressConfig
type FirewallConfig struct {
	log              logrus.FieldLogger
	egressIPConfig   map[uint32]map[uint32]uint32
	egressCIDRConfig map[uint32][MaxCIDREntries]CIDR
}

type CIDR struct {
	Address uint64
	Mask    uint64
}

func newFirewallConfig(log logrus.FieldLogger, dnsServer []string) *FirewallConfig {
	return &FirewallConfig{
		log:            log,
		egressIPConfig: make(map[uint32]map[uint32]uint32),
	}
}
