package indices

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	v1alpha1 "github.com/moolen/skouter/api"
	dnscache "github.com/moolen/skouter/pkg/cache/dns"
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/metrics"
	"github.com/moolen/skouter/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var logger = log.DefaultLogger.WithName("indices")

func Generate(
	ctx context.Context,
	k8sDynClient *dynamic.DynamicClient,
	k8sClientSet *kubernetes.Clientset,
	dnsCache *dnscache.Cache, allowedDNS []uint32,
	nodeIP, nodeName string, gwAddr uint32, gwIfAddr uint32,
) (AddressIndex, CIDRIndex, HostIndex, RuleIndex, error) {
	start := time.Now()
	defer metrics.UpdateIndices.With(nil).Observe(time.Since(start).Seconds())
	addrIdx := make(AddressIndex)
	cidrIdx := make(CIDRIndex)
	hostIdx := make(HostIndex)
	ruleIdx := make(RuleIndex)
	unstructured, err := k8sDynClient.Resource(v1alpha1.EgressGroupVersionResource).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, unstructuredEgress := range unstructured.Items {
		var egress v1alpha1.Egress
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(unstructuredEgress.Object, &egress)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// prepare allowed egress ips
		hosts := []string{}
		egressIPs := map[uint32]uint32{}
		egressCIDRs := map[string]*net.IPNet{}
		egressRegexs := map[string]*regexp.Regexp{}

		for _, rule := range egress.Spec.Rules {
			hosts = append(hosts, rule.Domains...)
			// add static ips
			for _, ip := range rule.IPs {
				key := util.IPToUint(net.ParseIP(ip))
				egressIPs[key] = 1
			}
			// add dynamic ips (without fqdns)
			for _, domain := range rule.Domains {
				addrs := dnsCache.Lookup(domain)
				if addrs == nil {
					continue
				}
				for addr := range addrs {
					egressIPs[addr] = 1
				}
			}

			for _, cidr := range rule.CIDRs {
				_, net, err := net.ParseCIDR(cidr)
				if err != nil {
					logger.Error(err, "unable to parse cidr", "cidr", cidr)
					continue
				}
				egressCIDRs[net.String()] = net
			}

			for _, fqdnRule := range rule.FQDN {
				re, err := regexp.Compile(fqdnRule)
				if err != nil {
					logger.Error(err, "unable to compile regexp", "rule", fqdnRule)
					continue
				}
				egressRegexs[fqdnRule] = re
			}
		}

		// add allowed dns servers
		for _, addr := range allowedDNS {
			egressIPs[addr] = 1
		}

		// add localhost CIDR 127.0.0.1/8
		egressCIDRs["127.0.0.1/8"] = &net.IPNet{
			IP:   net.IP{0x7f, 0x0, 0x0, 0x0},
			Mask: net.IPMask{0xff, 0x0, 0x0, 0x0}}

		// handle host firewall
		if egress.Spec.NodeSelector != nil {
			// check if node matches selector
			node, err := k8sClientSet.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
			if err != nil {
				continue
			}
			sel := labels.SelectorFromValidatedSet(labels.Set(egress.Spec.NodeSelector.MatchLabels))
			if !sel.Matches(labels.Set(node.ObjectMeta.Labels)) {
				logger.V(1).Info("egress node selector doesn't match labels of this node", "egress", egress.ObjectMeta.Name)
				continue
			}

			key := util.IPToUint(net.ParseIP(nodeIP))
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if ruleIdx[key] == nil {
				ruleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// host firewall needs to be allowed to send traffic to
			// the default gateway and to localhost
			egressIPs[gwAddr] = 1
			egressIPs[gwIfAddr] = 1

			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(ruleIdx[key], egressRegexs)

			for _, hostname := range hosts {
				if hostIdx[hostname] == nil {
					hostIdx[hostname] = make(map[uint32]struct{})
				}
				hostIdx[hostname][key] = struct{}{}
			}
			continue
		}

		podList, err := k8sClientSet.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + nodeName,
			LabelSelector: labels.FormatLabels(egress.Spec.PodSelector.MatchLabels),
		})
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("unable to list pods: %w", err)
		}

		// for every pod: prepare address and hostname indices
		// so we can do a lookup by pod key
		for _, pod := range podList.Items {
			// we do not want to apply policies for pods
			// that are on the host network.
			if pod.Status.PodIP == "" || pod.Spec.HostNetwork {
				continue
			}
			podIP := net.ParseIP(pod.Status.PodIP)
			if podIP == nil {
				logger.Error(err, "unable to parse ip", "addr", pod.Status.PodIP)
				continue
			}
			key := util.IPToUint(podIP)
			if addrIdx[key] == nil {
				addrIdx[key] = make(map[uint32]uint32)
			}
			if cidrIdx[key] == nil {
				cidrIdx[key] = make(map[string]*net.IPNet)
			}
			if ruleIdx[key] == nil {
				ruleIdx[key] = make(map[string]*regexp.Regexp)
			}
			// add known IPs/CIDRs to map
			mergeKeyMap(addrIdx[key], egressIPs)
			mergeNetMap(cidrIdx[key], egressCIDRs)
			mergeRegexpMap(ruleIdx[key], egressRegexs)

			for _, host := range hosts {
				// we need to normalize this to a fqdn
				hostname := host
				if !strings.HasSuffix(host, ".") {
					hostname += "."
				}
				if hostIdx[hostname] == nil {
					hostIdx[hostname] = make(map[uint32]struct{})
				}
				hostIdx[hostname][key] = struct{}{}
				mergeHostMap(addrIdx[key], dnsCache.Lookup(hostname))
			}
		}
	}
	return addrIdx, cidrIdx, hostIdx, ruleIdx, nil
}

// copy keys from source into the dest map
func mergeNetMap(dest map[string]*net.IPNet, src map[string]*net.IPNet) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

func mergeRegexpMap(dest map[string]*regexp.Regexp, src map[string]*regexp.Regexp) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeKeyMap(dest map[uint32]uint32, src map[uint32]uint32) {
	if src == nil {
		return
	}
	for k, v := range src {
		dest[k] = v
	}
}

// copy keys from source into the dest map
func mergeHostMap(dest map[uint32]uint32, src map[uint32]struct{}) {
	if src == nil {
		return
	}
	for k := range src {
		dest[k] = 1
	}
}
