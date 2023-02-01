package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/util"
)

type EgressCIDRConfig struct {
	*ebpf.Map
}

var (
	innerCIDRMap = &ebpf.MapSpec{
		Name:       "pod_egress_cidr_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  8, // 8 bytes for u64 IPv4 + mask
		MaxEntries: 256,
	}
)

func (e *EgressCIDRConfig) Update(key uint32, cidrs map[string]*net.IPNet) error {

	// set up outer map and store CIDRs
	var innerID ebpf.MapID
	err := e.Lookup(key, &innerID)
	if err == nil {
		return e.UpdateInner(innerID, key, cidrs)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unable to lookup egress config: %s", err.Error())
	}

	m, err := ebpf.NewMap(innerCIDRMap)
	if err != nil {
		return fmt.Errorf("unable to create inner map: %s", err.Error())
	}
	defer m.Close()
	inf, err := m.Info()
	if err != nil {
		return fmt.Errorf("unable to get egress config map info: %s", err.Error())
	}
	var ok bool
	innerID, ok = inf.ID()
	if !ok {
		return fmt.Errorf("unable to get egress config map id: %s", err.Error())
	}
	err = e.Put(key, uint32(m.FD()))
	if err != nil {
		return fmt.Errorf("cannot put egress cidr config key: %s", err)
	}
	return e.UpdateInner(innerID, key, cidrs)
}

func (e *EgressCIDRConfig) UpdateInner(innerID ebpf.MapID, key uint32, cidrMap map[string]*net.IPNet) error {
	m, err := ebpf.NewMapFromID(innerID)
	if err != nil {
		return fmt.Errorf("unable to access inner map: %s", err.Error())
	}
	defer m.Close()

	// idx=0 holds the number of cidrs
	numCIDRs := len(cidrMap)
	err = m.Put(uint32(0), uint64(numCIDRs))
	if err != nil {
		return fmt.Errorf("unable to store cidr len key=%s, len=%d", util.ToIP(key), numCIDRs)
	}

	// allow CIDRs
	// index 1..256
	for i, cidr := range orderedCIDRMap(cidrMap) {
		idx := i + 1
		err = m.Put(uint32(idx), cidr)
		if err != nil {
			return fmt.Errorf("unable to put cidr key=%d cidr=%s: %s", key, util.ToNetMask(cidr.Addr, cidr.Mask), err)
		}
	}
	return nil
}

func orderedCIDRMap(cidr map[string]*net.IPNet) []CidrConfigVal {
	keys := []string{}
	for k := range cidr {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []CidrConfigVal{}
	for _, key := range keys {
		val := cidr[key]
		if val.IP.IsUnspecified() || bytes.Equal(val.Mask, []byte{0, 0, 0, 0}) {
			continue
		}
		bpfVal := CidrConfigVal{
			Addr: util.IPToUint(val.IP),
			Mask: util.MaskToUint(val.Mask),
		}
		out = append(out, bpfVal)
	}
	return out
}
