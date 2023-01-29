package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/util"
)

// reconcileAddrMap sweeps through all key/value pairs in egressConfig
// and removes orphaned keys
func (c *Controller) reconcileAddrMap() error {
	start := time.Now()
	defer reconcileAddrMap.With(nil).Observe(time.Since(start).Seconds())
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()

	// first: write new data to bpf maps
	update := func(innerID ebpf.MapID, key uint32, staticAddrs map[uint32]uint32) {
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Errorf("unable to access inner map: %s", err.Error())
			return
		}
		defer m.Close()

		// allow static IPs
		for addr, setting := range staticAddrs {
			err = m.Put(addr, setting)
			if err != nil {
				c.log.Errorf("unable to put static ip key=%d addr=%d: %s", key, addr, err)
			}
		}
	}

	// set up outer map and store IPs
	for key, staticAddrs := range c.addrIdx {
		var innerID ebpf.MapID
		err := c.egressConfig.Lookup(key, &innerID)
		if err == nil {
			update(innerID, key, staticAddrs)
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup egress config: %s", err.Error())
			continue
		}

		m, err := ebpf.NewMap(innerIPMap)
		if err != nil {
			c.log.Errorf("unable to create inner map: %s", err.Error())
			continue
		}
		defer m.Close()
		inf, err := m.Info()
		if err != nil {
			c.log.Errorf("unable to get egress config map info: %s", err.Error())
			continue
		}
		var ok bool
		innerID, ok = inf.ID()
		if !ok {
			c.log.Errorf("unable to get egress config map id: %s", err.Error())
			continue
		}
		err = c.egressConfig.Put(key, uint32(m.FD()))
		if err != nil {
			return fmt.Errorf("cannot put egress config key: %s", err)
		}
		update(innerID, key, staticAddrs)
	}

	it := c.egressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := c.addrIdx[key]; !ok {
			c.log.Debugf("reconciling egress, removing key=%s", keyToIP(key))
			err := c.egressConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Warnf("unable to reconcile pod key=%s %s", keyToIP(key), err.Error())
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to get map from inner id key=%s id=%d: %s", keyToIP(key), innerID, err.Error())
			continue
		}
		iit := m.Iterate()
		var destAddr uint32
		var allowed uint32
		for iit.Next(&destAddr, &allowed) {
			// case: state exists in bpf map where it shouldn't
			if _, ok := c.addrIdx[key][destAddr]; !ok {

				// make sure this is not a regexp
				if c.reCache.HasAddr(destAddr) {
					continue
				}

				c.log.Debugf("reconciling egress ips, removing key=%s ip=%s", keyToIP(key), keyToIP(destAddr))
				err = m.Delete(destAddr)
				if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
					c.log.Warnf("unable to delete key=%s dest=%s", keyToIP(key), keyToIP(destAddr))
				}
				continue
			}
		}
	}
	return nil
}

// reconcileCIDRMap sweeps through all key/value paris in egressCIDRConfig
// and removes orphaned pods
func (c *Controller) reconcileCIDRMap() error {
	start := time.Now()
	defer reconcileCIDRMap.With(nil).Observe(time.Since(start).Seconds())
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()
	update := func(innerID ebpf.MapID, key uint32, cidrMap map[string]*net.IPNet) {
		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Errorf("unable to access inner map: %s", err.Error())
			return
		}
		defer m.Close()

		// idx=0 holds the number of cidrs
		numCIDRs := len(cidrMap)
		err = m.Put(uint32(0), uint64(numCIDRs))
		if err != nil {
			c.log.Errorf("unable to store cidr len key=%s, len=%d", util.ToIP(key), numCIDRs)
			return
		}

		// allow CIDRs
		// index 1..256
		for i, cidr := range orderedCIDRMap(cidrMap) {
			idx := i + 1
			err = m.Put(uint32(idx), cidr)
			if err != nil {
				c.log.Errorf("unable to put cidr key=%d cidr=%s: %s", key, util.ToNetMask(cidr.Addr, cidr.Mask), err)
			}
		}
	}

	// set up outer map and store CIDRs
	for key, cidrs := range c.cidrIdx {
		var innerID ebpf.MapID
		err := c.egressCIDRConfig.Lookup(key, &innerID)
		if err == nil {
			update(innerID, key, cidrs)
			continue
		}
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			c.log.Errorf("unable to lookup egress config: %s", err.Error())
			continue
		}

		m, err := ebpf.NewMap(innerCIDRMap)
		if err != nil {
			c.log.Errorf("unable to create inner map: %s", err.Error())
			continue
		}
		defer m.Close()
		inf, err := m.Info()
		if err != nil {
			c.log.Errorf("unable to get egress config map info: %s", err.Error())
			continue
		}
		var ok bool
		innerID, ok = inf.ID()
		if !ok {
			c.log.Errorf("unable to get egress config map id: %s", err.Error())
			continue
		}
		err = c.egressCIDRConfig.Put(key, uint32(m.FD()))
		if err != nil {
			return fmt.Errorf("cannot put egress cidr config key: %s", err)
		}
		update(innerID, key, cidrs)
	}

	it := c.egressCIDRConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := c.cidrIdx[key]; !ok {
			c.log.Debugf("reconciling egress cidr, removing key=%s", keyToIP(key))
			err := c.egressCIDRConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				c.log.Warnf("unable to reconcile pod cidr key=%s %s", keyToIP(key), err.Error())
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			c.log.Warnf("unable to get cidr map from inner id key=%s id=%d: %s", keyToIP(key), innerID, err.Error())
			continue
		}
		iit := m.Iterate()
		var i uint32
		var cidr bpfCidrConfigVal

		for iit.Next(&i, &cidr) {
			if i != 0 && // idx=0 contains size
				i >= uint32(len(c.cidrIdx[key])+1) && // we might have stale values at the end
				cidr.Addr != 0 &&
				cidr.Mask != 0 {
				c.log.Debugf("reconciling egress CIDRs, removing key=%s cidr=%s", keyToIP(key), util.ToNetMask(cidr.Addr, cidr.Mask).String())
				err = m.Delete(i)
				if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
					c.log.Warnf("unable to delete key=%s cidr=%s", keyToIP(key), util.ToNetMask(cidr.Addr, cidr.Mask).String())
				}
				continue
			}
		}
	}
	return nil
}

func orderedCIDRMap(cidr map[string]*net.IPNet) []bpfCidrConfigVal {
	keys := []string{}
	for k := range cidr {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []bpfCidrConfigVal{}
	for _, key := range keys {
		val := cidr[key]
		if val.IP.IsUnspecified() || bytes.Equal(val.Mask, []byte{0, 0, 0, 0}) {
			continue
		}
		bpfVal := bpfCidrConfigVal{
			Addr: util.IPToUint(val.IP),
			Mask: util.MaskToUint(val.Mask),
		}
		out = append(out, bpfVal)
	}
	return out
}
