package bpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jackpal/gateway"
	v1alpha1 "github.com/moolen/skouter/api"
	dnscache "github.com/moolen/skouter/pkg/dns_cache"
	"github.com/moolen/skouter/pkg/wildcard"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event -type cidr_config_val bpf ./c/cgroup_skb.c -- -I./c/headers
type Controller struct {
	ctx context.Context

	k8sConfig    *rest.Config
	k8sClientSet *kubernetes.Clientset
	k8sDynClient *dynamic.DynamicClient

	log        logrus.FieldLogger
	reg        *prometheus.Registry
	auditMode  bool
	nodeName   string
	nodeIP     string
	updateChan chan struct{}
	cgroupfs   string
	bpffs      string
	gwAddr     uint32
	gwIfAddr   uint32
	allowedDNS []uint32
	dnsCache   *dnscache.Cache
	reCache    *wildcard.Cache

	idxMu *sync.RWMutex
	// hostIdx is a map: hostname => map[pod-key]=>allowed-state
	hostIdx HostIndex
	ruleIdx RuleIndex
	addrIdx AddressIndex
	cidrIdx CIDRIndex

	ingressProg *ebpf.Program
	egressProg  *ebpf.Program

	egressConfig       *ebpf.Map
	egressCIDRConfig   *ebpf.Map
	dnsConfig          *ebpf.Map
	eventsMap          *ebpf.Map
	metricsMap         *ebpf.Map
	metricsBlockedAddr *ebpf.Map

	ingressLink link.Link
	egressLink  link.Link
}

type AddressIndex map[uint32]map[uint32]uint32

type CIDRIndex map[uint32]map[string]*net.IPNet

type HostIndex map[string]map[uint32]struct{}

type RuleIndex map[uint32]map[string]*regexp.Regexp

var (
	// Action used by the bpf program
	// needs to be in sync with cgroup_skb.c
	// TODO: pull these settings from bytecode so there's no need to sync
	ActionAllow = uint32(1)

	BPFMountDir = "skouter"

	// inner map must be in sync with cgroup_skb.c
	innerIPMap = &ebpf.MapSpec{
		Name:       "pod_egress_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  4, // 4 bytes for u32
		MaxEntries: 4096,
	}

	// inner cidr must be in sync with cgroup_skb.c
	innerCIDRMap = &ebpf.MapSpec{
		Name:       "pod_egress_cidr_config",
		Type:       ebpf.Hash,
		KeySize:    4, // 4 bytes for u32
		ValueSize:  8, // 8 bytes for u64 IPv4 + mask
		MaxEntries: 256,
	}
)

func New(
	ctx context.Context,
	k8sConfig *rest.Config,
	cgroupfs,
	bpffs,
	nodeName,
	nodeIP,
	cacheStoragePath string,
	allowedDNS []string,
	auditMode bool,
	log logrus.FieldLogger,
	reg *prometheus.Registry) (*Controller, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var dnsAddrs []uint32
	for _, dnsAddr := range allowedDNS {
		dnsIP := net.ParseIP(dnsAddr)
		if dnsIP == nil {
			return nil, fmt.Errorf("invalid ip addr: %s", dnsIP)
		}
		dnsAddrs = append(dnsAddrs, binary.LittleEndian.Uint32(dnsIP.To4()))
	}

	// TODO: make that configurable/extensible through CLI
	//       a user may need to specify an IP address from a different interface
	gwAddr, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	gwIfAddr, err := gateway.DiscoverInterface()
	if err != nil {
		return nil, err
	}

	log.Infof("discovered gateway=%s if=%s", gwAddr.String(), gwIfAddr.String())

	wc := wildcard.New(log, cacheStoragePath)
	wc.Restore()
	go wc.Autosave(ctx, time.Second*15)

	clientSet, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	ctrl := &Controller{
		ctx:          ctx,
		log:          log,
		k8sConfig:    k8sConfig,
		k8sClientSet: clientSet,
		k8sDynClient: dynClient,
		reg:          reg,
		updateChan:   make(chan struct{}),

		cgroupfs:   cgroupfs,
		bpffs:      bpffs,
		allowedDNS: dnsAddrs,
		gwAddr:     binary.LittleEndian.Uint32(gwAddr.To4()),
		gwIfAddr:   binary.LittleEndian.Uint32(gwIfAddr.To4()),
		dnsCache:   dnscache.New(log),
		reCache:    wc,
		nodeName:   nodeName,
		nodeIP:     nodeIP,
		auditMode:  auditMode,
		idxMu:      &sync.RWMutex{},
		hostIdx:    HostIndex{},
	}

	err = ctrl.loadBPF()
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}

func (c *Controller) Run() error {
	newMetricsCollector(c.reg, c)

	err := c.startPodWatcher()
	if err != nil {
		return fmt.Errorf("unable to start pod watcher: %w", err)
	}
	err = c.startEgressWatcher()
	if err != nil {
		return fmt.Errorf("unable to start egress watcher: %w", err)
	}

	// == initialisation process ==
	//
	// Before we _enforce_ egress traffic
	// we must ensure that pre-existing connections to allowed hosts
	// won't be impacted by us.
	//
	// To do so we'll issue DNS queries to find allowed IP addresses
	// and store them before we block traffic.
	//
	// 1. do not block egress traffic
	// 2. query & store allowed hosts' IP addresses
	// 3. block egress.

	// set the upstream dns server
	c.log.Infof("setting allowed dns: %d", c.allowedDNS)
	for _, addr := range c.allowedDNS {
		err := c.dnsConfig.Put(addr, uint32(1)) // value isn't used
		if err != nil {
			return fmt.Errorf("unable to set dns config: %w", err)
		}
	}

	// pre-warm DNS cache and allow-list IPs
	err = c.preWarm()
	if err != nil {
		return fmt.Errorf("unable to prewarm: %s", err)
	}
	go c.runDNSReader()

	// attach the program to cgroup
	err = c.attach()
	if err != nil {
		return fmt.Errorf("unable to attach to cgroup2: %s", err.Error())
	}

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case <-c.updateChan:
			err := c.updateConfig()
			if err != nil {
				c.log.Error(err)
			}
		}
	}
}

func (c *Controller) startPodWatcher() error {
	podWatch, err := c.k8sClientSet.CoreV1().Pods("").Watch(c.ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + c.nodeName,
	})
	if err != nil {
		c.log.Fatalf("unable to watch pods: %s", err.Error())
	}
	go func() {
		c.log.Infof("starting pod watcher")
		for {
			select {
			case ev := <-podWatch.ResultChan():
				if ev.Type == watch.Error || ev.Type == "" {
					continue
				}
				c.updateChan <- struct{}{}
			case <-c.ctx.Done():
				c.log.Infof("shutdown pod watcher")
				return
			}
		}
	}()

	return nil
}

func (c *Controller) startEgressWatcher() error {
	egressWatch, err := c.k8sDynClient.Resource(v1alpha1.EgressGroupVersionResource).Watch(c.ctx, metav1.ListOptions{})
	if err != nil {
		c.log.Fatalf("unable to watch egress: %s", err.Error())
	}
	go func() {
		c.log.Infof("starting egress watcher")
		for {
			select {
			case ev := <-egressWatch.ResultChan():
				if ev.Type == watch.Error || ev.Type == "" {
					continue
				}
				c.updateChan <- struct{}{}
			case <-c.ctx.Done():
				c.log.Infof("shutdown egress watcher")
				return
			}
		}
	}()

	return nil
}

func (c *Controller) preWarm() error {
	c.log.Infof("starting prewarm")
	// prepare bpf maps
	err := c.updateConfig()
	if err != nil {
		return fmt.Errorf("update config: %s", err)
	}

	c.idxMu.RLock()
	defer c.idxMu.RUnlock()

	for host, podKeys := range c.hostIdx {
		addrs := c.dnsCache.LookupIP(host)
		for _, addr := range addrs {
			hostAddr := addr.To4()
			if hostAddr == nil {
				continue
			}
			for podKey := range podKeys {
				err = c.AllowHosts([]string{host}, []net.IP{hostAddr}, podKey)
				if err != nil {
					c.log.Error(err)
				}
			}
		}
	}

	c.log.Info("done with prewarm")
	return nil
}

func (c *Controller) updateConfig() error {
	start := time.Now()
	defer func() {
		reconcileMaps.With(nil).Observe(time.Since(start).Seconds())
		c.log.Debugf("reconcile map: %f seconds", time.Since(start).Seconds())
	}()
	if err := c.updateIndices(); err != nil {
		return err
	}

	// reconcile bpf maps
	wcstart := time.Now()
	if err := c.reCache.ReconcileIndex(c.flattenRules()); err != nil {
		return err
	}
	reconcileRegexpCache.With(nil).Observe(time.Since(wcstart).Seconds())
	if err := c.reconcileAddrMap(); err != nil {
		return err
	}
	return c.reconcileCIDRMap()
}

func (c *Controller) updateIndices() error {
	start := time.Now()
	defer func() {
		updateIndices.With(nil).Observe(time.Since(start).Seconds())
		c.log.Debugf("update indices: %f seconds", time.Since(start).Seconds())
	}()
	addrIdx := make(AddressIndex)
	cidrIdx := make(CIDRIndex)
	hostIdx := make(HostIndex)
	ruleIdx := make(RuleIndex)
	unstructured, err := c.k8sDynClient.Resource(v1alpha1.EgressGroupVersionResource).List(c.ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, unstructuredEgress := range unstructured.Items {
		var egress v1alpha1.Egress
		err = runtime.DefaultUnstructuredConverter.
			FromUnstructured(unstructuredEgress.Object, &egress)
		if err != nil {
			return err
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
				key := keyForAddr(net.ParseIP(ip))
				egressIPs[key] = ActionAllow
			}
			// add dynamic ips (without wildcards)
			for _, domain := range rule.Domains {
				addrs := c.dnsCache.Lookup(domain)
				if addrs == nil {
					continue
				}
				for addr := range addrs {
					egressIPs[addr] = ActionAllow
				}
			}

			for _, cidr := range rule.CIDRs {
				_, net, err := net.ParseCIDR(cidr)
				if err != nil {
					c.log.Errorf("unable to parse cidr: %#v", err)
					continue
				}
				egressCIDRs[net.String()] = net
			}

			for _, reRule := range rule.Regexps {
				re, err := regexp.Compile(reRule)
				if err != nil {
					c.log.Error(err)
					continue
				}
				egressRegexs[reRule] = re
			}
		}

		// add allowed dns servers
		for _, addr := range c.allowedDNS {
			egressIPs[addr] = ActionAllow
		}

		// add localhost CIDR 127.0.0.1/8
		egressCIDRs["127.0.0.1/8"] = &net.IPNet{
			IP:   net.IP{0x7f, 0x0, 0x0, 0x0},
			Mask: net.IPMask{0xff, 0x0, 0x0, 0x0}}

		// handle host firewall
		if egress.Spec.NodeSelector != nil {
			// check if node matches selector
			node, err := c.k8sClientSet.CoreV1().Nodes().Get(c.ctx, c.nodeName, metav1.GetOptions{})
			if err != nil {
				continue
			}
			sel := labels.SelectorFromValidatedSet(labels.Set(egress.Spec.NodeSelector.MatchLabels))
			if !sel.Matches(labels.Set(node.ObjectMeta.Labels)) {
				c.log.Debugf("egress %s node selector %#v doesn't match labels of this node %s: %#v",
					&egress.ObjectMeta.Name, egress.Spec.NodeSelector.MatchLabels, c.nodeName, node.ObjectMeta.Labels)
				continue
			}

			key := keyForAddr(net.ParseIP(c.nodeIP))
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
			egressIPs[c.gwAddr] = ActionAllow
			egressIPs[c.gwIfAddr] = ActionAllow

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

		podList, err := c.k8sClientSet.CoreV1().Pods("").List(c.ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + c.nodeName,
			LabelSelector: labels.FormatLabels(egress.Spec.PodSelector.MatchLabels),
		})
		if err != nil {
			return fmt.Errorf("unable to list pods: %w", err)
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
				c.log.Errorf("unable to parse ip %q", podIP)
				continue
			}
			key := keyForAddr(podIP)
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
				mergeHostMap(addrIdx[key], c.dnsCache.Lookup(hostname))
			}
			c.log.Debugf("got pod %s/%s=>%s => %#v", pod.Namespace, pod.Name, pod.Status.PodIP, addrIdx[key])
		}
	}

	c.idxMu.Lock()
	defer c.idxMu.Unlock()
	c.addrIdx = addrIdx
	c.cidrIdx = cidrIdx
	c.hostIdx = hostIdx
	c.ruleIdx = ruleIdx

	return nil
}

func (c *Controller) Close() {
	c.log.Debug("closing bpf resources")
	c.egressProg.Close()
	c.ingressProg.Close()
	c.ingressLink.Close()
	c.egressLink.Close()

	// Flush wildcard cache to disk
	// so it can be restored
	err := c.reCache.Save()
	if err != nil {
		c.log.Error(err)
	}

	// uncomment to clean up map state
	// c.eventsMap.Unpin()
	// c.egressConfig.Unpin()
	// c.dnsConfig.Unpin()
	// c.metricsMap.Unpin()
	// c.metricsBlockedAddr.Unpin()

	c.eventsMap.Close()
	c.egressConfig.Close()
	c.dnsConfig.Close()
	c.metricsMap.Close()
	c.metricsBlockedAddr.Close()
}
