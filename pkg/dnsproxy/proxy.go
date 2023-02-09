package dnsproxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/miekg/dns"
	dnscache "github.com/moolen/skouter/pkg/cache/dns"
	"github.com/moolen/skouter/pkg/cache/fqdn"
	"github.com/moolen/skouter/pkg/indices"
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/metrics"
	"github.com/moolen/skouter/pkg/sock"
	"github.com/moolen/skouter/pkg/util"
)

type DNSProxy struct {
	// raw sockets for read/write
	rd *ringbuf.Reader

	UpstreamSocketCookies []uint64
	udpSockPool           *sock.UDPSocketPool
	UDPServer             *dns.Server
	TCPServer             *dns.Server

	rawConn   *net.IPConn
	dnsClient *dns.Client
	dnsCache  *dnscache.Cache
	fqdnCache *fqdn.Cache
	allowFunc func(key uint32, addr net.IP) error

	nodeIP             string
	trustedDNSEndpoint string

	mu      *sync.RWMutex
	hostIdx indices.HostIndex
	ruleIdx indices.RuleIndex
}

var logger = log.DefaultLogger.WithName("dnsproxy").V(1)

func NewProxy(rd *ringbuf.Reader, dnsCache *dnscache.Cache, fqdnCache *fqdn.Cache, allowFunc func(key uint32, addr net.IP) error,
	nodeIP, trustedDNSServer string) (*DNSProxy, error) {
	rawConn, err := (&net.ListenConfig{Control: sock.ControlFunc}).
		ListenPacket(context.Background(), "ip:udp", "127.0.0.1")
	if err != nil {
		return nil, err
	}

	connPool, cookies, err := sock.NewUDPPool(trustedDNSServer, 100)
	if err != nil {
		return nil, err
	}

	logger.Info("upstream socket cookies", "cookie", cookies)

	p := &DNSProxy{
		rd: rd,
		dnsClient: &dns.Client{
			Net:            "udp",
			Timeout:        time.Second * 2,
			SingleInflight: false,
		},
		rawConn:               rawConn.(*net.IPConn),
		dnsCache:              dnsCache,
		fqdnCache:             fqdnCache,
		allowFunc:             allowFunc,
		nodeIP:                nodeIP,
		trustedDNSEndpoint:    trustedDNSServer,
		UpstreamSocketCookies: cookies,
		udpSockPool:           connPool,

		mu:      &sync.RWMutex{},
		hostIdx: make(indices.HostIndex),
		ruleIdx: make(indices.RuleIndex),
	}

	udpConn, tcpListener, err := sock.BindToAddr("", 53)
	if err != nil {
		return nil, err
	}
	bindAddr := ":53"
	logger.Info("binding to addr", "addr", bindAddr)
	p.UDPServer = &dns.Server{
		PacketConn: udpConn,
		Addr:       bindAddr,
		Net:        "udp",
		Handler:    p,
	}
	p.TCPServer = &dns.Server{
		Listener: tcpListener,
		Addr:     bindAddr,
		Net:      "tcp",
		Handler:  p,
	}

	return p, nil
}

func (p *DNSProxy) Start() {
	logger.Info("starting dnsproxy")
	for _, s := range []*dns.Server{p.UDPServer, p.TCPServer} {
		go func(server *dns.Server) {
			err := server.ActivateAndServe()
			if err != nil {
				logger.Error(err, "unable to start srv")
			}
		}(s)
	}
}

func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	err := p.processPacket(w, msg)
	if err != nil {
		logger.Error(err, "unable to process packet")
	}
}

func (p *DNSProxy) processPacket(w dns.ResponseWriter, msg *dns.Msg) error {
	start := time.Now()
	defer metrics.ProcessDNSPacket.WithLabelValues().Observe(float64(time.Since(start)))
	logger.V(2).Info("processing DNS query", "local", w.LocalAddr(), "upstream", w.RemoteAddr(), "query", msg)
	dnsstart := time.Now()

	origId := msg.Id
	// force a new ID for this request
	msg.Id = dns.Id()
	logger.V(2).Info("sending to upstream DNS server", "local", w.LocalAddr(), "upstream", w.RemoteAddr(), "query", msg)

	sock, err := p.udpSockPool.Get()
	if err != nil {
		return err
	}
	defer p.udpSockPool.Put(sock)
	response, _, err := p.dnsClient.ExchangeWithConn(msg, &dns.Conn{Conn: sock.Conn})
	if err != nil {
		return fmt.Errorf("unable to exchange with upstream DNS server: %w", err)
	}
	metrics.DNSUpstreamLatency.WithLabelValues().Observe(float64(time.Since(dnsstart)))
	// set original id so the downstream client is able
	// to match the response to the original query.
	response.Id = origId
	msg.Id = origId
	localIP := net.ParseIP(p.nodeIP)
	if p.isFQDNAllowed(localIP, msg) {
		err = p.ObserveResponse(localIP, msg, response)
		if err != nil {
			return err
		}
	} else {
		// TODO: consider making this pluggable:
		// * either respond with NXDOMAIN
		// * or just send the response without allowing the specified IPs
		// problem with sending NXDOMAIN is that there may be a allow based on CIDR range
		// which then gets blocked by this DNS response
		//
		// logger.V(1).Info("rejecting traffic based on policy")
		// cpy := dns.Msg{}
		// cpy.SetRcode(msg, dns.RcodeNameError)
		// return p.WriteMsg(w, &cpy)
	}

	logger.V(2).Info("sending downstream response", "res", response)
	return p.WriteMsg(w, response)
}

func (p *DNSProxy) WriteMsg(rw dns.ResponseWriter, msg *dns.Msg) error {
	remoteIP, remotePort, err := net.SplitHostPort(rw.RemoteAddr().String())
	if err != nil {
		return err
	}
	dport, err := strconv.Atoi(remotePort)
	if err != nil {
		return err
	}
	w := &ResponseWriter{
		conn:       p.rawConn,
		localAddr:  net.ParseIP(p.nodeIP),
		localPort:  uint16(dport), // for some reason
		remoteAddr: net.ParseIP(remoteIP),
		remotePort: 53,
	}

	return w.WriteMsg(msg)
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

func (p *DNSProxy) UpdateAllowed(hostIdx indices.HostIndex, ruleIdx indices.RuleIndex) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hostIdx = hostIdx
	p.ruleIdx = ruleIdx
}
