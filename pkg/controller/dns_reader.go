package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/miekg/dns"
	"github.com/moolen/skouter/pkg/bpf"
	cache "github.com/moolen/skouter/pkg/cache/dns"
)

// runDNSReader starts reading from the eventsMap ringbuffer
// until it gets closed. It will parse the DNS packets
// and allows the associated IP if it matches an allowed host.
func (c *Controller) runDNSReader() {
	c.log.Infof("starting ringbuf reader")
	rd, err := ringbuf.NewReader(c.bpf.EventsMap)
	if err != nil {
		c.log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err == ringbuf.ErrClosed {
			c.log.Fatalf("closed event ringbuf reader, stop reconciling allow list: %s", err.Error())
			return
		} else if err != nil {
			c.log.Error(err)
			continue
		}
		err = c.processPacket(&record)
		if err != nil {
			c.log.Errorf("unable to process dns packet:%s", err.Error())
		}
	}
}

func (c *Controller) processPacket(record *ringbuf.Record) error {
	start := time.Now()
	defer processDNSPacket.With(nil).Observe(float64(time.Since(start).Seconds()))

	var event bpf.Event
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return fmt.Errorf("parsing ringbuf event: %w", err)
	}

	var msg dns.Msg
	err := msg.Unpack(event.Pkt[:event.Len])
	if err != nil {
		dnsParseError.WithLabelValues(c.nodeName, strconv.FormatInt(int64(event.Key), 10)).Inc()
		return fmt.Errorf("unable to unpack dns: ev: len=%d key=%s %#v %s", event.Len, keyToIP(event.Key), event.Pkt, err)
	}

	var hostnames []string
	var ips []net.IP
	minTTL := cache.DefaultTTL
	for _, a := range msg.Answer {
		// all hostnames are captured and passed to tryAllowAccess
		// which will check whether or not this one is allowed
		cname, ok := a.(*dns.CNAME)
		if ok {
			hostnames = append(hostnames, cname.Header().Name)
			if cname.Hdr.Ttl < uint32(minTTL.Seconds()) {
				minTTL = time.Duration(cname.Hdr.Ttl)
			}
			continue
		}
		// for now, only support ipv4
		arec, ok := a.(*dns.A)
		if !ok {
			continue
		}
		v4 := arec.A.To4()
		hostnames = append(hostnames, arec.Header().Name)
		if v4.Equal(net.IPv4(0, 0, 0, 0)) {
			continue
		}
		ips = append(ips, v4)
		if arec.Hdr.Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(arec.Hdr.Ttl)
		}
	}
	c.dnsCache.SetMany(hostnames, ips, minTTL)
	err = c.AllowHosts(hostnames, ips, event.Key)
	if err != nil && !errors.Is(err, ErrForbidden) {
		return fmt.Errorf("unable to update dns record state: %s", err.Error())
	}
	return nil
}

var ErrForbidden = fmt.Errorf("tried to access forbidden host")

// AllowHosts checks if a host from the supplied list is allowed to be accessed from the given pod.
// It will update the BPF map state and internal caches.
func (c *Controller) AllowHosts(hosts []string, ips []net.IP, key uint32) error {
	if len(hosts) == 0 || len(ips) == 0 {
		return nil
	}

	// see if there is a explicit host match
	var allowedByHost bool
	for _, host := range hosts {
		// check if host index contains the hostname that has been requested
		c.idxMu.RLock()
		addrIdx, ok := c.hostIdx[host]
		c.idxMu.RUnlock()
		if !ok {
			continue
		}
		// check if this pod is supposed to access this hostname
		_, ok = addrIdx[key]
		if ok {
			allowedByHost = true
		}
	}

	hostRule, allowedRE := c.regexpAllowed(hosts, ips, key)
	if allowedRE {
		if err := c.reStore.Observe(hostRule, hosts, ips); err != nil {
			c.log.Error(err)
		}
	}

	if !allowedByHost && !allowedRE {
		for _, host := range hosts {
			lookupForbiddenHostname.WithLabelValues(c.nodeName, strconv.FormatUint(uint64(key), 10), host).Inc()
		}
		return fmt.Errorf("%w: key=%s host=%s", ErrForbidden, keyToIP(key), hosts[0])
	}

	for _, addr := range ips {
		resolvedAddr := binary.LittleEndian.Uint32(addr)
		c.log.Infof("unblocking resolved addr: daddr=%s key=%s", keyToIP(resolvedAddr), keyToIP(key))

		var innerID ebpf.MapID
		err := c.bpf.EgressConfig.Lookup(key, &innerID)
		if err != nil {
			return fmt.Errorf("unable to lookup outer map: %s", err.Error())
		}
		innerMap, err := ebpf.NewMapFromID(innerID)
		if err != nil {
			return fmt.Errorf("unable to create inner map from fd: %s", err.Error())
		}
		err = innerMap.Put(&resolvedAddr, &ActionAllow)
		if err != nil {
			return fmt.Errorf("unable to put map: %s", err.Error())
		}
	}

	// Indices must be reconciled for the regexp cache to converge.
	// otherwise deletes won't propagate
	// This is a costly operation, the events are debounced at the receiver side
	// c.updateChan <- struct{}{}
	return nil
}

func (c *Controller) regexpAllowed(hostnames []string, ips []net.IP, key uint32) (string, bool) {
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()
	rules := c.ruleIdx[key]
	for _, hostname := range hostnames {
		// hostname has a trailing `.` (FQDN)
		hostname := strings.TrimSuffix(hostname, ".")
		for reRule, re := range rules {
			if re.MatchString(hostname) {
				return reRule, true
			}
		}
	}
	return "", false
}
