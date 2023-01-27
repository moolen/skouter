package cache

import (
	"net"
	"strings"

	"github.com/moolen/skouter/pkg/util"
)

func (c *Cache) Lookup(hostname string) map[uint32]struct{} {
	hostname = normalizeHostname(hostname)
	data, ok := c.hostnameData.Get(hostname)
	if ok {
		return data
	}

	// lookup address and store it
	addrs, err := net.LookupIP(hostname)
	if err != nil {
		c.log.Errorf("unable to lookup hostname %s: %s", hostname, err.Error())
		return nil
	}
	data = make(map[uint32]struct{})
	for _, addr := range addrs {
		data[util.IPToUint(addr)] = struct{}{}
	}

	c.hostnameData.Set(hostname, data, DefaultTTL)
	return data
}

func (c *Cache) SetMany(hostnames []string, addrs []net.IP) {
	data := make(map[uint32]struct{})
	for _, addr := range addrs {
		data[util.IPToUint(addr)] = struct{}{}
	}

	for _, hostname := range hostnames {
		hostname = normalizeHostname(hostname)
		c.hostnameData.Set(hostname, data, DefaultTTL)
	}
}

func (c *Cache) LookupIP(hostname string) []net.IP {
	data := c.Lookup(hostname)
	if data == nil {
		return nil
	}
	var addrs []net.IP
	for nAddr := range data {
		addr := util.ToIP(nAddr)
		if addr == nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func normalizeHostname(hostname string) string {
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}
	return hostname
}
