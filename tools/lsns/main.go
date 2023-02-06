package main

import (
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/netns"
)

var logger = log.DefaultLogger

func main() {

	rootIno, err := netns.RootNS()
	if err != nil {
		panic(err)
	}
	logger.Info("got root ns", "ino", rootIno)
	logger.Info("listing net ns")

	nss, err := netns.List()
	if err != nil {
		panic(err)
	}
	for _, ns := range nss {

		logger.Info("got ns", "ns", ns)

		// TODO:
		// in order to support DNS over TCP
		// we must hijack the traffic and send it to our own dnsproxy socket.
		// This can be done with the sk_lookup hook pointing to our dnsproxy socket
		// which listens on both udp+tcp.
		// sk_lookup can only be attached to individual network namespaces, hence
		// we must find the appropriate cgroups and ns/net attached to it.
		//
		// cgroup:
		// /{...}/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-podb2d0a672_f1b8
		//
		//
		// 1. attach to sk_lookup hook
		// 2. shift traffic over to dnsproxy
		// 3. return response via net_raw
	}
}
