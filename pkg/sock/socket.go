package sock

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var SockoptMark = 0x520
var DefaultDialer = &net.Dialer{
	Timeout: time.Second * 2,
	Control: ControlFunc,
}

var ControlFunc = func(network, address string, c syscall.RawConn) error {
	var operr error
	err := c.Control(func(fd uintptr) {
		operr = transparentSetsockopt(int(fd), true)
		if operr == nil && SockoptMark != 0 {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SockoptMark)
		}
		if operr == nil {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}
	})
	if err != nil {
		return err
	}
	return operr
}

// Set the socket options needed for tranparent proxying for the listening socket
// IP_TRANSPARENT allows socket to receive packets with any destination address/port
// IP_RECVORIGDSTADDR tells the kernel to pass the original destination address/port on recvmsg
// The socket may be receiving both IPv4 and IPv6 data, so set both options, if enabled.
func transparentSetsockopt(fd int, ipv4 bool) error {
	var err4 error
	if ipv4 {
		err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		if err4 == nil {
			err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
		if err4 != nil {
			return err4
		}
	}
	return nil
}
