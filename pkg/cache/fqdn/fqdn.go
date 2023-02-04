package fqdn

import (
	"encoding/json"
	"net"

	"github.com/moolen/skouter/pkg/util"
)

// Observe should be called to store a DNS response from a bunch of hosts/addrs.
// It writes the observed hostnames / ip addresses to the internal cache
func (c *Cache) Observe(fqdn string, hosts []string, addrs []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var data map[string]map[uint32]uint32
	var ok bool
	data, ok = c.fqdnData.Get(fqdn)
	if !ok {
		data = make(map[string]map[uint32]uint32)
	}

	for _, hostname := range hosts {
		var addrMap map[uint32]uint32
		addrMap, ok = data[hostname]
		if !ok {
			addrMap = make(map[uint32]uint32)
		}

		for _, addr := range addrs {
			uintAddr := util.IPToUint(addr)
			addrMap[uintAddr] = uint32(1) // allow

			data[hostname] = addrMap
			c.fqdnData.Set(fqdn, data, 0)

			// update idx
			var fqdnMap map[string]map[string]uint32
			fqdnMap, ok = c.fqdnIdx.Get(uintAddr)
			if !ok {
				fqdnMap = make(map[string]map[string]uint32)
			}
			var hostMap map[string]uint32
			hostMap, ok = fqdnMap[fqdn]
			if !ok {
				hostMap = make(map[string]uint32)
			}
			hostMap[hostname] = uint32(1) // alow
			fqdnMap[fqdn] = hostMap
			c.fqdnIdx.Set(uintAddr, fqdnMap, 0)
		}
	}

	return nil
}

// DumpMap dumps the maps contents
func (c *Cache) DumpMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.fqdnData.Keys() {
		data, _ := c.fqdnData.Get(k)
		datas, _ := json.Marshal(data)
		logger.Info("fqdn data dump", "key", k, "value", string(datas))
	}

	for _, k := range c.fqdnIdx.Keys() {
		data, _ := c.fqdnIdx.Get(k)
		datas, _ := json.Marshal(data)
		logger.Info("fqdn index dump", "key", k, "value", string(datas))
	}
}

// Reconciles the internal state with the given ruleIdx.
// This evicts IPs from both index and data caches.
func (c *Cache) ReconcileIndex(desiredFQDNs map[string]struct{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logger.Info("reconciling re cache", "data", c.fqdnData.Keys(), "index", c.fqdnIdx.Keys(), "desired-fqdns", desiredFQDNs)
	for _, fqdn := range c.fqdnData.Keys() {
		// case: rule still exists: ignore
		if _, ok := desiredFQDNs[fqdn]; ok {
			continue
		}
		// case: rule was removed: cleanup data + index
		staleData, ok := c.fqdnData.Get(fqdn)
		if !ok {
			continue
		}
		logger.Info("stale data", "data", staleData)
		// delete addr from index
		for _, addrMap := range staleData {
			for addr := range addrMap {
				logger.Info("checking idx", "addr", addr)
				idxData, ok := c.fqdnIdx.Get(addr)
				if !ok {
					continue
				}
				delete(idxData, fqdn)
				if len(idxData) == 0 {
					logger.Info("deleting idx", "key", addr)
					c.fqdnIdx.Invalidate(addr)
				} else {
					logger.Info("updating idx data", "idx", idxData)
					c.fqdnIdx.Set(addr, idxData, 0)
				}
			}
		}
		c.fqdnData.Invalidate(fqdn)
	}

	return nil
}

// HasAddr returns true if the given address exists
// in cache and hence is allow-listed.
func (c *Cache) HasAddr(addr uint32) bool {
	_, ok := c.fqdnIdx.Get(addr)
	return ok
}
