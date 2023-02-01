package bpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"regexp"
)

func (c *Controller) flattenRules() map[string]struct{} {
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()
	out := make(map[string]struct{})
	for _, rule := range c.ruleIdx {
		for re := range rule {
			out[re] = struct{}{}
		}
	}
	return out
}

func keyToIP(addr uint32) string {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, addr)
	return net.IP(buf.Bytes()).To4().String()
}
func keyForAddr(addr net.IP) uint32 {
	return binary.LittleEndian.Uint32(addr.To4())
}

// copy keys from source into the dest map
func mergeNetMap(dest map[string]*net.IPNet, src map[string]*net.IPNet) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

func mergeRegexpMap(dest map[string]*regexp.Regexp, src map[string]*regexp.Regexp) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeKeyMap(dest map[uint32]uint32, src map[uint32]uint32) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeHostMap(dest map[uint32]uint32, src map[uint32]struct{}) {
	if src == nil {
		return
	}
	for k := range src {
		dest[k] = ActionAllow
	}
}
