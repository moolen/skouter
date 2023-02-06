package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
)

type DNSProxy struct {
	rd        *ringbuf.Reader
	rawConn   *net.IPConn
	dnsClient *dns.Client
	dnsCache  *dnscache.Cache
	fqdnCache *fqdn.Cache
	allowFunc func(key uint32, addr net.IP) error

	mu      *sync.RWMutex
	hostIdx indices.HostIndex
	ruleIdx indices.RuleIndex
	cidrIdx indices.CIDRIndex
	addrIdx indices.AddressIndex
}

var logger = log.DefaultLogger.WithName("dnsproxy").V(1)

func NewProxy(rd *ringbuf.Reader, dnsCache *dnscache.Cache, fqdnCache *fqdn.Cache, allowFunc func(key uint32, addr net.IP) error) (*DNSProxy, error) {
	rawConn, err := (&net.ListenConfig{Control: sock.ControlFunc}).
		ListenPacket(context.Background(), "ip:udp", "127.0.0.1")
	if err != nil {
		return nil, err
	}

	return &DNSProxy{
		rd: rd,
		dnsClient: &dns.Client{
			Net:            "udp",
			Timeout:        time.Second * 2,
			SingleInflight: false,
			Dialer:         sock.DefaultDialer,
		},
		rawConn:   rawConn.(*net.IPConn),
		dnsCache:  dnsCache,
		fqdnCache: fqdnCache,
		allowFunc: allowFunc,
		mu:        &sync.RWMutex{},
		hostIdx:   make(indices.HostIndex),
		ruleIdx:   make(indices.RuleIndex),
		cidrIdx:   make(indices.CIDRIndex),
		addrIdx:   make(indices.AddressIndex),
	}, nil
}

func (p *DNSProxy) Start() {
	logger.Info("starting ringbuf reader")
	for {
		record, err := p.rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			logger.Error(err, "closed event ringbuf reader, stop reconciling allow list")
			return
		} else if err != nil {
			logger.Error(err, "unexpected ringbuf read error")
			continue
		}
		go func() {
			var event bpf.Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				logger.Error(err, "parsing ringbuf event")
				return
			}

			var msg dns.Msg
			err := msg.Unpack(event.Pkt[:event.Len])
			if err != nil {
				metrics.DNSParseError.WithLabelValues(strconv.FormatInt(int64(event.PodAddr), 10)).Inc()
				return
			}

			wr := resWriterfromEvent(p.rawConn, &event)
			err = p.processPacket(wr, &msg)
			if err != nil {
				logger.Error(err, "unable to process dns packet")
			}
		}()
	}
}

func (p *DNSProxy) processPacket(w DNSResponseWriter, msg *dns.Msg) error {
	start := time.Now()
	defer metrics.ProcessDNSPacket.WithLabelValues().Observe(float64(time.Since(start)))
	logger.V(2).Info("processing DNS query", "local", w.LocalAddr(), "upstream", w.RemoteAddr(), "query", msg)
	dnsstart := time.Now()
	conn, err := p.dnsClient.Dial(w.RemoteAddr().String())
	if err != nil {
		return err
	}
	defer conn.Close()

	origId := msg.Id
	// force a new ID for this request
	msg.Id = dns.Id()
	logger.V(2).Info("sending to upstream DNS server", "local", w.LocalAddr(), "upstream", w.RemoteAddr(), "query", msg)
	response, _, err := p.dnsClient.ExchangeWithConn(msg, conn)
	if err != nil {
		return err
	}
	metrics.DNSUpstreamLatency.WithLabelValues().Observe(float64(time.Since(dnsstart)))
	// set original id so the downstream client is able
	// to match the response to the original query.
	response.Id = origId
	msg.Id = origId

	if p.isFQDNAllowed(w.LocalAddr().IP, msg) || p.isAddrAllowed(w.LocalAddr().IP, response) {
		err = p.ObserveResponse(w.LocalAddr().IP, msg, response)
		if err != nil {
			return err
		}
	}

	logger.V(2).Info("sending downstream response", "res", response)
	return w.WriteMsg(response)
}

func (p *DNSProxy) isFQDNAllowed(podIP net.IP, msg *dns.Msg) bool {
	podAddr := util.IPToUint(podIP)
	p.mu.RLock()
	defer p.mu.RUnlock()
	rules := p.ruleIdx[podAddr]
	for _, q := range msg.Question {
		hostname := strings.TrimSuffix(q.Name, ".")
		addr, ok := p.hostIdx[hostname]
		if ok {
			if _, ok := addr[podAddr]; ok {
				return true
			}
		}
		for _, re := range rules {
			if re.MatchString(hostname) {
				return true
			}
		}
	}
	return false
}

func (p *DNSProxy) isAddrAllowed(podIP net.IP, msg *dns.Msg) bool {
	podAddr := util.IPToUint(podIP)
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, a := range msg.Answer {
		arec, ok := a.(*dns.A)
		if !ok {
			continue
		}
		// check ip
		uaddr := util.IPToUint(arec.A)
		allowedAddrs := p.addrIdx[podAddr]
		for addr := range allowedAddrs {
			if addr == uaddr {
				return true
			}
		}
		// check cidr
		allowedCIDRs := p.cidrIdx[podAddr]
		for _, cidr := range allowedCIDRs {
			if cidr.Contains(arec.A) {
				return true
			}
		}
	}
	return false
}

// we need to process the DNS response to allow
// this particular set of IPs
func (p *DNSProxy) ObserveResponse(podIP net.IP, req, res *dns.Msg) error {
	podAddr := util.IPToUint(podIP)
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

func (p *DNSProxy) UpdateAllowed(hostIdx indices.HostIndex, ruleIdx indices.RuleIndex, cidrIdx indices.CIDRIndex, addrIdx indices.AddressIndex) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hostIdx = hostIdx
	p.cidrIdx = cidrIdx
	p.ruleIdx = ruleIdx
	p.addrIdx = addrIdx
}
