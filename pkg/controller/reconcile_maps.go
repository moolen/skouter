package bpf

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/util"
)

// reconcileAddrMap sweeps through all key/value pairs in egressConfig
// and removes orphaned keys
func (c *Controller) reconcileAddrMap() error {
	start := time.Now()
	defer reconcileAddrMap.With(nil).Observe(time.Since(start).Seconds())
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()

	// update egress ips
	for key, staticAddrs := range c.addrIdx {
		err := c.bpf.EgressConfig.Update(key, staticAddrs)
		if err != nil {
			return err
		}
	}

	it := c.bpf.EgressConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := c.addrIdx[key]; !ok {
			c.log.Debugf("reconciling egress, removing key=%s", keyToIP(key))
			err := c.bpf.EgressConfig.Delete(key)
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
				if c.reStore.HasAddr(destAddr) {
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

// reconcileCIDRMap sweeps through all key/value pairs in egressCIDRConfig
// and removes orphaned pods
func (c *Controller) reconcileCIDRMap() error {
	start := time.Now()
	defer reconcileCIDRMap.With(nil).Observe(time.Since(start).Seconds())
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()

	// todo: implement update using batch API
	// see: https://lwn.net/Articles/797808/
	for key, cidrs := range c.cidrIdx {
		err := c.bpf.EgressCIDRConfig.Update(key, cidrs)
		if err != nil {
			return fmt.Errorf("unable to update egress cidr config: %w", err)
		}
	}

	it := c.bpf.EgressCIDRConfig.Iterate()
	var key uint32
	var innerID ebpf.MapID
	for it.Next(&key, &innerID) {
		// case: state exists in ebpf where it shouldn't
		if _, ok := c.cidrIdx[key]; !ok {
			c.log.Debugf("reconciling egress cidr, removing key=%s", keyToIP(key))
			err := c.bpf.EgressCIDRConfig.Delete(key)
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
		var cidr bpf.CidrConfigVal

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
