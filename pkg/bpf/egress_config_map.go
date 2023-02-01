package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type EgressConfig struct {
	*ebpf.Map
}

var (
	// inner map must be in sync with cgroup_skb.c
	innerIPMap = &ebpf.MapSpec{
		Name:       "pod_egress_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  4, // 4 bytes for u32
		MaxEntries: 4096,
	}
)

func (e *EgressConfig) Update(key uint32, staticAddrs map[uint32]uint32) error {
	var innerID ebpf.MapID
	err := e.Lookup(key, &innerID)
	if err == nil {
		// case: inner map already exists, call update straight away
		return e.UpdateInner(innerID, key, staticAddrs)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	// case: inner map doesn't exist yet
	m, err := ebpf.NewMap(innerIPMap)
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
		return fmt.Errorf("cannot put egress config key: %s", err)
	}
	return e.UpdateInner(innerID, key, staticAddrs)
}

func (e *EgressConfig) UpdateInner(innerID ebpf.MapID, key uint32, staticAddrs map[uint32]uint32) error {
	// first: write new data to bpf maps
	m, err := ebpf.NewMapFromID(innerID)
	if err != nil {
		return fmt.Errorf("unable to access inner map: %s", err.Error())
	}
	defer m.Close()

	// allow static IPs
	for addr, setting := range staticAddrs {
		err = m.Put(addr, setting)
		if err != nil {
			return fmt.Errorf("unable to put static ip key=%d addr=%d: %s", key, addr, err)
		}
	}
	return nil
}
