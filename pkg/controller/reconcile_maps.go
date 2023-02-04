package controller

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/metrics"
	"github.com/moolen/skouter/pkg/util"
)

// reconcileAddrMap sweeps through all key/value pairs in egressConfig
// and removes orphaned keys
func (c *Controller) reconcileAddrMap() error {
	start := time.Now()
	defer metrics.ReconcileAddrMap.With(nil).Observe(time.Since(start).Seconds())
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
			logger.Info("reconciling egress, removing key", "key", keyToIP(key))
			err := c.bpf.EgressConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				logger.Error(err, "unable to reconcile pod", "key", keyToIP(key))
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			logger.Error(err, "unable to get map from inner id", "key", keyToIP(key), "inner-map-id", innerID)
			continue
		}
		iit := m.Iterate()
		var destAddr uint32
		var allowed uint32
		for iit.Next(&destAddr, &allowed) {
			// case: state exists in bpf map where it shouldn't
			if _, ok := c.addrIdx[key][destAddr]; !ok {
				// make sure this is not a regexp
				if c.fqdnStore.HasAddr(destAddr) {
					continue
				}
				logger.Info("reconciling egress ips, removing key", "key", keyToIP(key), "dest-addr", keyToIP(destAddr))
				err = m.Delete(destAddr)
				if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
					logger.Error(err, "unable to delete key", "key", keyToIP(key), "dest-addr", keyToIP(destAddr))
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
	defer metrics.ReconcileCIDRMap.With(nil).Observe(time.Since(start).Seconds())
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
			logger.Info("reconciling egress cidr, removing key", "key", keyToIP(key))
			err := c.bpf.EgressCIDRConfig.Delete(key)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				logger.Error(err, "unable to reconcile pod cidr", "key", keyToIP(key))
			}
			continue
		}

		m, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			logger.Error(err, "unable to get cidr map from inner id", "key", keyToIP(key), "inner-map-id", innerID)
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
				logger.Info("reconciling egress CIDRs, removing key", "key", keyToIP(key), "cidr", util.ToNetMask(cidr.Addr, cidr.Mask).String())
				err = m.Delete(i)
				if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					logger.Error(err, "unable to delete key", "key", keyToIP(key), "cidr", util.ToNetMask(cidr.Addr, cidr.Mask).String())
				}
				continue
			}
		}
	}
	return nil
}
