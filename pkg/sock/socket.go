package sock

import (
	"context"
	"net"
	"strconv"
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
		operr = setSockopt(fd)
	})
	if err != nil {
		return err
	}
	return operr
}

var setSockopt = func(fd uintptr) error {
	operr := transparentSetsockopt(int(fd), true)
	if operr == nil && SockoptMark != 0 {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SockoptMark)
	}
	if operr == nil {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	return operr
}

func BindToAddr(address string, port uint16, ipv4 bool) (*net.UDPConn, uintptr, *net.TCPListener, uintptr, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn
	defer func() {
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	var tcpFd uintptr
	var udpFd uintptr
	bindAddr := net.JoinHostPort(address, strconv.Itoa(int(port)))
	listener, err = (&net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			_ = c.Control(func(fd uintptr) {
				tcpFd = fd
				err = setSockopt(fd)
			})
			return err
		},
	}).Listen(context.Background(),
		"tcp", bindAddr)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	conn, err = (&net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			_ = c.Control(func(fd uintptr) {
				udpFd = fd
				err = setSockopt(fd)
			})
			return err
		},
	}).ListenPacket(context.Background(),
		"udp", listener.Addr().String())
	if err != nil {
		return nil, 0, nil, 0, err
	}
	return conn.(*net.UDPConn), udpFd, listener.(*net.TCPListener), tcpFd, nil
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
