package metrics

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	logger = log.DefaultLogger.WithName("metrics")

	PacketsProcessed = prometheus.NewDesc(
		"packets_processed",
		"Number of packets processed",
		[]string{"node", "path", "type"}, nil,
	)
	// TODO: limit cardinality on this one
	AuditBlockedAddr = prometheus.NewDesc(
		"audit_blocked_addr",
		"Number of blocked packets in audit mode",
		[]string{"node", "ip"}, nil,
	)
	LookupForbiddenHostname = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lookup_forbidden_hostname",
	}, []string{"node", "key", "hostname"})
	DNSParseError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_parse_error",
	}, []string{"key"})
	DNSUpstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "dns_upstream_latency",
	}, nil)
	ReconcileMaps = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "reconcile_maps",
	}, nil)
	UpdateIndices = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "update_indices",
	}, nil)
	ReconcileAddrMap = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "reconcile_addr_map",
	}, nil)
	ReconcileCIDRMap = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "reconcile_cidr_map",
	}, nil)
	ReconcileRegexpCache = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "reconcile_regexp_cache",
	}, nil)
	ProcessDNSPacket = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "process_dns_packet",
		Buckets: []float64{0.000001, 0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.001},
	}, nil)
)

var (
	// sync with egress.c
	METRICS_EGRESS_ALLOWED = uint32(1)
	METRICS_EGRESS_BLOCKED = uint32(2)
	METRICS_EGRESS_DNS     = uint32(3)
)

type MetricsCollector struct {
	nodeName           string
	metricsMap         *ebpf.Map
	metricsBlockedAddr *ebpf.Map
}

func NewCollector(metricsMap, metricsBlockedAddr *ebpf.Map, nodeName string) {
	prometheus.MustRegister(LookupForbiddenHostname)
	prometheus.MustRegister(DNSParseError)
	prometheus.MustRegister(DNSUpstreamLatency)
	prometheus.MustRegister(ReconcileMaps)
	prometheus.MustRegister(UpdateIndices)
	prometheus.MustRegister(ReconcileAddrMap)
	prometheus.MustRegister(ReconcileCIDRMap)
	prometheus.MustRegister(ReconcileRegexpCache)
	prometheus.MustRegister(ProcessDNSPacket)
	prometheus.MustRegister(&MetricsCollector{
		nodeName:           nodeName,
		metricsMap:         metricsMap,
		metricsBlockedAddr: metricsBlockedAddr,
	})
}

func (cc MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(cc, ch)
}

func (cc MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// metric index in bpf map => label value
	// indices are defined in egress.c
	metrics := map[uint32][]string{
		METRICS_EGRESS_ALLOWED: {cc.nodeName, "EGRESS", "ALLOW"},
		METRICS_EGRESS_BLOCKED: {cc.nodeName, "EGRESS", "BLOCK"},
		METRICS_EGRESS_DNS:     {cc.nodeName, "EGRESS", "ALLOW_DNS"},
	}

	for key, lblValues := range metrics {
		var val uint32
		err := cc.metricsMap.Lookup(key, &val)
		if err != nil && err != ebpf.ErrKeyNotExist {
			continue
		}
		ch <- prometheus.MustNewConstMetric(PacketsProcessed, prometheus.CounterValue, float64(val), lblValues...)
	}

	it := cc.metricsBlockedAddr.Iterate()
	var addr uint32
	var count uint32
	for it.Next(&addr, &count) {
		var buf bytes.Buffer
		err := binary.Write(&buf, binary.LittleEndian, addr)
		if err != nil {
			logger.Error(err, "unable to write binary addr")
			continue
		}
		ipAddr := net.IP(buf.Bytes())
		ch <- prometheus.MustNewConstMetric(AuditBlockedAddr, prometheus.CounterValue, float64(count), cc.nodeName, ipAddr.String())
	}
}
