package wildcard

import (
	"encoding/json"
	"net"

	"github.com/moolen/skouter/pkg/util"
)

// Observe should be called to store a DNS response from a bunch of hosts/addrs.
// It writes the observed hostnames / ip addresses to the internal cache
func (c *Cache) Observe(wildcard string, hosts []string, addrs []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var data map[string]map[uint32]uint32
	var ok bool
	data, ok = c.wildcardData.Get(wildcard)
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
			c.wildcardData.Set(wildcard, data, 0)

			// update idx
			var wildcardMap map[string]map[string]uint32
			wildcardMap, ok = c.wildcardIdx.Get(uintAddr)
			if !ok {
				wildcardMap = make(map[string]map[string]uint32)
			}
			var hostMap map[string]uint32
			hostMap, ok = wildcardMap[wildcard]
			if !ok {
				hostMap = make(map[string]uint32)
			}
			hostMap[hostname] = uint32(1) // alow
			wildcardMap[wildcard] = hostMap
			c.wildcardIdx.Set(uintAddr, wildcardMap, 0)
		}
	}

	return nil
}

// DumpMap dumps the maps contents
func (c *Cache) DumpMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.wildcardData.Keys() {
		data, _ := c.wildcardData.Get(k)
		datas, _ := json.Marshal(data)
		c.log.Debugf("data[%s] => %s", k, string(datas))
	}

	for _, k := range c.wildcardIdx.Keys() {
		data, _ := c.wildcardIdx.Get(k)
		datas, _ := json.Marshal(data)
		c.log.Debugf("idx[%d] => %s", k, string(datas))
	}
}

// Reconciles the internal state with the given ruleIdx.
// This evicts IPs from both index and data caches.
func (c *Cache) ReconcileIndex(desiredWildcards map[string]struct{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.log.Debugf("reconciling wc idx: %#v | %#v", c.wildcardData.Keys(), c.wildcardIdx.Keys())
	for _, wildcard := range c.wildcardData.Keys() {
		// case: rule still exists: ignore
		if _, ok := desiredWildcards[wildcard]; ok {
			continue
		}
		// case: rule was removed: cleanup data + index
		staleData, ok := c.wildcardData.Get(wildcard)
		if !ok {
			continue
		}
		c.log.Debugf("stale date: %#v", staleData)
		// delete addr from index
		for _, addrMap := range staleData {
			for addr := range addrMap {
				c.log.Debugf("checking idx: %#v", addr)
				idxData, ok := c.wildcardIdx.Get(addr)
				if !ok {
					continue
				}
				delete(idxData, wildcard)
				if len(idxData) == 0 {
					c.log.Debugf("deleting idx key: %#v", addr)
					c.wildcardIdx.Invalidate(addr)
				} else {
					c.log.Debugf("updating idx data: %#v", idxData)
					c.wildcardIdx.Set(addr, idxData, 0)
				}
			}
		}
		c.wildcardData.Invalidate(wildcard)
	}

	return nil
}

// HasAddr returns true if the given address exists
// in cache and hence is allow-listed.
func (c *Cache) HasAddr(addr uint32) bool {
	_, ok := c.wildcardIdx.Get(addr)
	return ok
}
