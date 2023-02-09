package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func deleteQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscDel(qdisc)
}

// attachProgram attaches prog to link.
func attachProgram(deviceName string, prog *ebpf.Program) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", deviceName, err)
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("skouter-%s", link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %w", err)
	}

	return nil
}

func detachProgram(deviceName string, prog *ebpf.Program) error {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", deviceName, err)
	}
	err = netlink.FilterDel(&netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("skouter-%s", link.Attrs().Name),
		DirectAction: true,
	})

	if err != nil {
		return err
	}
	return deleteQdisc(link)
}
