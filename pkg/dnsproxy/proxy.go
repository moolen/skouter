package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/miekg/dns"
	"github.com/moolen/skouter/pkg/bpf"
	dnscache "github.com/moolen/skouter/pkg/cache/dns"
	"github.com/moolen/skouter/pkg/cache/fqdn"
	"github.com/moolen/skouter/pkg/indices"
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/metrics"
	"github.com/moolen/skouter/pkg/sock"
	"github.com/moolen/skouter/pkg/util"
	"golang.org/x/net/ipv4"
)

type DNSProxy struct {
	rd        *ringbuf.Reader
	ipconn    *net.IPConn
	dnsCache  *dnscache.Cache
	fqdnCache *fqdn.Cache
	allowFunc func(key uint32, addr net.IP) error

	mu      *sync.RWMutex
	hostIdx indices.HostIndex
	ruleIdx indices.RuleIndex
	cidrIdx indices.CIDRIndex
}

var logger = log.DefaultLogger.WithName("dnsproxy").V(1)

func NewProxy(rd *ringbuf.Reader, dnsCache *dnscache.Cache, fqdnCache *fqdn.Cache, allowFunc func(key uint32, addr net.IP) error) (*DNSProxy, error) {
	p := &DNSProxy{
		rd:        rd,
		dnsCache:  dnsCache,
		fqdnCache: fqdnCache,
		allowFunc: allowFunc,
		mu:        &sync.RWMutex{},
		hostIdx:   make(indices.HostIndex),
		ruleIdx:   make(indices.RuleIndex),
		cidrIdx:   make(indices.CIDRIndex),
	}
	conn, err := net.ListenPacket("ip:udp", "127.0.0.1")
	if err != nil {
		return nil, err
	}
	p.ipconn = conn.(*net.IPConn)
	return p, nil
}

func (p *DNSProxy) Start() {
	logger.Info("starting ringbuf reader")
	for {
		record, err := p.rd.Read()
		if err == ringbuf.ErrClosed {
			logger.Error(err, "closed event ringbuf reader, stop reconciling allow list")
			return
		} else if err != nil {
			logger.Error(err, "unexpected ringbuf read error")
			continue
		}
		go func() {
			err = p.processPacket(&record)
			if err != nil {
				logger.Error(err, "unable to process dns packet")
			}
		}()
	}
}

func (p *DNSProxy) processPacket(record *ringbuf.Record) error {
	start := time.Now()
	defer metrics.ProcessDNSPacket.With(nil).Observe(float64(time.Since(start).Seconds()))

	var event bpf.Event
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return fmt.Errorf("parsing ringbuf event: %w", err)
	}

	var msg dns.Msg
	err := msg.Unpack(event.Pkt[:event.Len])
	if err != nil {
		metrics.DNSParseError.WithLabelValues(strconv.FormatInt(int64(event.PodAddr), 10)).Inc()
		return nil
	}

	allowed, err := p.CheckAllowed(event.PodAddr, &msg)
	if err != nil {
		return err
	}
	if !allowed {
		logger.Info("rejecting DNS query by policy")
		res := new(dns.Msg)
		res.SetRcode(&msg, dns.RcodeNameError)

		return p.SendDownstream(
			util.ToIP(event.DstAddr),
			util.ToIP(event.PodAddr),
			util.ToNetBytes16(event.DstPort),
			util.ToNetBytes16(event.PodPort),
			res,
		)
	}

	// send to upstream DNS server
	client := &dns.Client{
		Net:            "udp",
		Timeout:        time.Second * 2,
		SingleInflight: false,
		Dialer:         sock.DefaultDialer,
	}
	dialAddr := fmt.Sprintf("%s:%d", util.ToIP(event.DstAddr), util.ToHost16(event.DstPort))
	conn, err := client.Dial(dialAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	origId := msg.Id
	msg.Id = dns.Id() // force a random new ID for this request
	response, _, err := client.ExchangeWithConn(&msg, conn)
	if err != nil {
		return err
	}

	err = p.ObserveResponse(event.PodAddr, &msg, response)
	if err != nil {
		return err
	}

	response.Id = origId
	return p.SendDownstream(
		util.ToIP(event.DstAddr),
		util.ToIP(event.PodAddr),
		util.ToNetBytes16(event.DstPort),
		util.ToNetBytes16(event.PodPort),
		response,
	)
}

func (p *DNSProxy) CheckAllowed(podAddr uint32, msg *dns.Msg) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rules := p.ruleIdx[podAddr]
	for _, q := range msg.Question {
		hostname := q.Name
		addr, ok := p.hostIdx[hostname]
		if ok {
			if _, ok := addr[podAddr]; ok {
				return true, nil
			}
		}
		for _, re := range rules {
			if re.MatchString(hostname) {
				return true, nil
			}
		}
		requestedAddr := p.dnsCache.Lookup(hostname)
		allowedCIDRs := p.cidrIdx[podAddr]
		for _, cidr := range allowedCIDRs {
			for addr := range requestedAddr {
				if cidr.Contains(util.ToIP(addr)) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// we need to process the DNS response to allow
// this particular set of IPs
func (p *DNSProxy) ObserveResponse(podAddr uint32, req, res *dns.Msg) error {
	var addrs []net.IP
	for _, ans := range res.Answer {
		arec, ok := ans.(*dns.A)
		if ok {
			err := p.allowFunc(podAddr, arec.A)
			if err != nil {
				logger.WithValues("pod", podAddr).Error(err, "unable to allow")
				continue
			}
			addrs = append(addrs, arec.A)
		}
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	rules := p.ruleIdx[podAddr]
	var matchedfqdn string
	var matchedHost []string
	for _, q := range req.Question {
		hostname := strings.TrimSuffix(q.Name, ".")
		for fqdn, re := range rules {
			if re.MatchString(hostname) {
				matchedfqdn = fqdn
				matchedHost = append(matchedHost, hostname)
				break
			}
		}
	}

	if matchedfqdn == "" {
		return nil // nothing to do
	}
	return p.fqdnCache.Observe(matchedfqdn, matchedHost, addrs)
}

func (p *DNSProxy) UpdateAllowed(hostIdx indices.HostIndex, ruleIdx indices.RuleIndex, cidrIdx indices.CIDRIndex) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hostIdx = hostIdx
	p.cidrIdx = cidrIdx
	p.ruleIdx = ruleIdx
}

func (p *DNSProxy) SendDownstream(srcAddr, podAddr net.IP, srcPort, podPort uint16, msg *dns.Msg) error {
	logger.Info("sending to downstream", "src", srcAddr, "dst", podAddr, "dns", msg)
	lc := net.ListenConfig{
		Control: sock.ControlFunc,
	}

	c, err := lc.ListenPacket(context.Background(), "ip:udp", "127.0.0.1")
	if err != nil {
		return err
	}
	ic := c.(*net.IPConn)

	b, err := msg.Pack()
	if err != nil {
		return err
	}

	l := len(b)
	bb := bytes.NewBuffer(nil)
	_ = binary.Write(bb, binary.BigEndian, uint16(srcPort))
	_ = binary.Write(bb, binary.BigEndian, uint16(podPort))
	_ = binary.Write(bb, binary.BigEndian, uint16(8+l))
	_ = binary.Write(bb, binary.BigEndian, uint16(0)) // checksum
	_, _ = bb.Write(b)
	buf := bb.Bytes()

	cm := new(ipv4.ControlMessage)
	cm.Src = srcAddr

	_, _, err = ic.WriteMsgIP(buf, cm.Marshal(), &net.IPAddr{
		IP: podAddr,
	})
	return err
}
