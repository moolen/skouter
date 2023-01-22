package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	packetsProcessed = prometheus.NewDesc(
		"packets_processed",
		"Number of packets processed",
		[]string{"path", "type"}, nil,
	)
	lookupForbiddenHostname = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "lookup_forbidden_hostname",
	}, []string{"key", "hostname"})
	dnsParseError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_parse_error",
	}, []string{"key"})
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
		1: {"EGRESS", "ALLOW"},
		2: {"EGRESS", "BLOCK"},
		3: {"EGRESS", "ALLOW_DNS"},
		4: {"INGRESS", "TXID_MISMATCH"},
		5: {"INGRESS", "ROGUE_DNS"},
	}

	for key, lblValues := range metrics {
		var val uint32
		err := cc.controller.metricsMap.Lookup(key, &val)
		if err != nil && err != ebpf.ErrKeyNotExist {
			continue
		}
		ch <- prometheus.MustNewConstMetric(packetsProcessed, prometheus.CounterValue, float64(val), lblValues...)
	}
}
