package controller

import (
	"bytes"
	"encoding/binary"
	"net"
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
