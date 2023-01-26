package cache

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/moolen/skouter/pkg/util"
)

// Store the host
func (c *Cache) Observe(wildcard string, hosts []string, addrs []net.IP) error {
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

func (c *Cache) DumpMap() {
	for _, k := range c.wildcardData.Keys() {

		data, _ := c.wildcardData.Get(k)
		datas, _ := json.Marshal(data)
		fmt.Printf("data[%s] => %s\n", k, string(datas))
	}

	for _, k := range c.wildcardIdx.Keys() {
		data, _ := c.wildcardIdx.Get(k)
		datas, _ := json.Marshal(data)
		fmt.Printf("idx[%d] => %s\n", k, string(datas))
	}
}

// Store the host
func (c *Cache) ReconcileIndex(ruleIdx map[uint32]map[string]*regexp.Regexp) error {
	desiredWildcards := make(map[string]string)
	for _, rule := range ruleIdx {
		for wildcard := range rule {
			desiredWildcards[wildcard] = wildcard
		}
	}

	for _, wildcard := range c.wildcardData.Keys() {
		// case: rule was removed
		if _, ok := desiredWildcards[wildcard]; !ok {
			staleData, ok := c.wildcardData.Get(wildcard)
			if !ok {
				continue
			}
			// delete addr from index
			for _, addrMap := range staleData {
				for addr := range addrMap {
					idxData, ok := c.wildcardIdx.Get(addr)
					if !ok {
						continue
					}
					delete(idxData, wildcard)
					if len(idxData) == 0 {
						c.wildcardIdx.Invalidate(addr)
					} else {
						c.wildcardIdx.Set(addr, idxData, 0)
					}
				}
			}
			c.wildcardData.Invalidate(wildcard)
		}
	}

	return nil
}

func (c *Cache) HasAddr(addr uint32) bool {
	_, ok := c.wildcardIdx.Get(addr)
	return ok
}
