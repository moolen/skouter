package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/moolen/skouter/pkg/log"
)

type CidrConfigVal bpfCidrConfigVal
type DNSServerEndpoint bpfDnsServerEndpoint
type ProxyRedirectConfig bpfProxyRedirectConfig
type ProxyRedirectDMAC bpfProxyRedirectDmac

var (
	// Name of the directory in /sys/fs/bpf that holds the pinned maps/progs
	BPFMountDir = "skouter"
	logger      = log.DefaultLogger.WithName("bpf").V(1)
)

type LoadedCollection struct {
	HostEgress *ebpf.Program
	deviceName string

	EgressConfig         *EgressConfig
	EgressCIDRConfig     *EgressCIDRConfig
	ProxySocketCookieMap *ebpf.Map
	ProxyRedirectMap     *ebpf.Map
	ProxyRedirectDMACMap *ebpf.Map
	DNSConfig            *ebpf.Map
	MetricsMap           *ebpf.Map
	MetricsBlockedAddr   *ebpf.Map
	EventsMap            *ebpf.Map
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type dns_server_endpoint -type proxy_redirect_config -type proxy_redirect_dmac -type cidr_config_val bpf ./c/egress.c -- -I./c/headers
func Load(bpffs string, auditMode bool) (*LoadedCollection, error) {
	pinPath := filepath.Join(bpffs, BPFMountDir)
	err := os.MkdirAll(pinPath, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create bpf fs subpath %q: %+v", pinPath, err)
	}

	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	if auditMode {
		if err := spec.RewriteConstants(map[string]interface{}{
			"audit_mode": uint32(1),
		}); err != nil {
			return nil, err
		}
	}
	err = spec.LoadAndAssign(&objs.bpfMaps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	})
	if err != nil {
		return nil, err
	}
	err = spec.LoadAndAssign(&objs.bpfPrograms, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ebpf.ProgramOptions{
			LogSize: 1024 * 1024,
		},
	})
	ve := &ebpf.VerifierError{}
	if errors.As(err, &ve) {
		fmt.Println(strings.Join(ve.Log, "\n"))
		logger.Error(err, "unable to load bpf prog")
	}
	if err != nil {
		return nil, err
	}
	return &LoadedCollection{
		HostEgress: objs.bpfPrograms.Classifier,

		EgressConfig:         &EgressConfig{objs.bpfMaps.EgressConfig},
		EgressCIDRConfig:     &EgressCIDRConfig{objs.bpfMaps.EgressCidrConfig},
		ProxySocketCookieMap: objs.bpfMaps.ProxySocketCookie,
		ProxyRedirectMap:     objs.bpfMaps.ProxyRedirectMap,
		ProxyRedirectDMACMap: objs.bpfMaps.ProxyRedirectDmacMap,
		DNSConfig:            objs.bpfMaps.DnsConfig,
		MetricsMap:           objs.bpfMaps.Metrics,
		MetricsBlockedAddr:   objs.bpfMaps.MetricsBlockedAddr,
		EventsMap:            objs.bpfMaps.Events,
	}, nil
}

func (coll *LoadedCollection) Attach(deviceName string) error {
	var err error
	logger.Info("attaching to device", "device", deviceName)
	coll.deviceName = deviceName
	err = attachProgram(deviceName, coll.HostEgress)
	if err != nil {
		return err
	}

	return nil
}

func (coll *LoadedCollection) Close() error {
	logger.Info("unloading bpf programs/maps")

	err := detachProgram(coll.deviceName, coll.HostEgress)
	if err != nil {
		logger.Error(err, "unable to detach program", "device", coll.deviceName)
	}
	logger.Info("detached program", "device", coll.deviceName)

	coll.HostEgress.Close()
	coll.EventsMap.Close()
	coll.EgressConfig.Close()
	coll.ProxyRedirectMap.Close()
	coll.ProxyRedirectDMACMap.Close()
	coll.EgressCIDRConfig.Close()
	coll.ProxySocketCookieMap.Close()
	coll.DNSConfig.Close()
	coll.MetricsMap.Close()
	coll.MetricsBlockedAddr.Close()
	return nil
}
