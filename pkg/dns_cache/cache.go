package cache

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/sirupsen/logrus"
)

type Cache struct {
	log          logrus.FieldLogger
	hostnameData cache.Cache[string, map[uint32]struct{}]
}

const (
	MaxKeys    = 8192
	DefaultTTL = time.Minute * 5
)

func New(log logrus.FieldLogger) *Cache {
	return &Cache{
		log: log,
		hostnameData: cache.NewCache[string, map[uint32]struct{}]().
			WithMaxKeys(MaxKeys).
			WithTTL(DefaultTTL),
	}
}

func (c *Cache) Lookup(hostname string) map[uint32]struct{} {
	hostname = normalizeHostname(hostname)
	data, ok := c.hostnameData.Get(hostname)
	if ok {
		return data
	}

	// lookup address and store it
	addrs, err := net.LookupIP(hostname)
	if err != nil {
		c.log.Error("unable to lookup hostname %s: %s", hostname, err.Error())
		return nil
	}
	data = make(map[uint32]struct{})
	for _, addr := range addrs {
		data[toUint(addr)] = struct{}{}
	}

	c.hostnameData.Set(hostname, data, DefaultTTL)
	return data
}

func (c *Cache) SetMany(hostnames []string, addrs []net.IP) {
	data := make(map[uint32]struct{})
	for _, addr := range addrs {
		data[toUint(addr)] = struct{}{}
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
		addr := toIP(nAddr)
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

func toUint(addr net.IP) uint32 {
	addr = addr.To4()
	if addr == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(addr)
}

func toIP(addr uint32) net.IP {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, addr)
	if err != nil {
		return nil
	}
	return net.IP(buf.Bytes())
}
