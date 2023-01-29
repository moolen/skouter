package bpf

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	packetsProcessed = prometheus.NewDesc(
		"packets_processed",
		"Number of packets processed",
		[]string{"node", "path", "type"}, nil,
	)
	// TODO: limit cardinality on this one
	auditBlockedAddr = prometheus.NewDesc(
		"audit_blocked_addr",
		"Number of blocked packets in audit mode",
		[]string{"node", "ip"}, nil,
	)
	lookupForbiddenHostname = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lookup_forbidden_hostname",
	}, []string{"node", "key", "hostname"})
	dnsParseError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_parse_error",
	}, []string{"node", "key"})
)

func newMetricsCollector(reg prometheus.Registerer, c *Controller) {
	reg.MustRegister(lookupForbiddenHostname)
	reg.MustRegister(&MetricsCollector{
		controller: c,
	})
}

type MetricsCollector struct {
	controller *Controller
}

func (cc MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// metric index in bpf map => label value
	// indices are defined in cgroup_skb.c
	metrics := map[uint32][]string{
		1: {cc.controller.nodeName, "EGRESS", "ALLOW"},
		2: {cc.controller.nodeName, "EGRESS", "BLOCK"},
		3: {cc.controller.nodeName, "EGRESS", "ALLOW_DNS"},
		4: {cc.controller.nodeName, "INGRESS", "TXID_MISMATCH"},
		5: {cc.controller.nodeName, "INGRESS", "ROGUE_DNS"},
	}

	for key, lblValues := range metrics {
		var val uint32
		err := cc.controller.metricsMap.Lookup(key, &val)
		if err != nil && err != ebpf.ErrKeyNotExist {
			continue
		}
		ch <- prometheus.MustNewConstMetric(packetsProcessed, prometheus.CounterValue, float64(val), lblValues...)
	}

	it := cc.controller.metricsBlockedAddr.Iterate()
	var addr uint32
	var count uint32
	for it.Next(&addr, &count) {
		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, addr)
		if err != nil {
			cc.controller.log.Warnf("unable to write binary addr: %s", err.Error())
			continue
		}
		ipAddr := net.IP(buf.Bytes())
		ch <- prometheus.MustNewConstMetric(auditBlockedAddr, prometheus.CounterValue, float64(count), cc.controller.nodeName, ipAddr.String())
	}
}
