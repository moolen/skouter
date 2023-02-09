package sock

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var SockoptMark = 0xb00

var DefaultDialer = &net.Dialer{
	Timeout: time.Second * 2,
	Control: ControlFunc,
}

var CookieDialer = func() (*net.Dialer, *uint64) {
	var cookie uint64
	return &net.Dialer{
		Timeout: time.Second * 2,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			err := c.Control(func(fd uintptr) {
				operr = setSockopt(fd)
				if operr == nil {
					cookie, operr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
				}
			})
			if err != nil {
				return err
			}
			return operr
		},
	}, &cookie
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
	operr := transparentSetsockopt(int(fd))
	if operr == nil && SockoptMark != 0 {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SockoptMark)
	}
	if operr == nil {
		operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	return operr
}

func BindToAddr(address string, port uint16) (*net.UDPConn, *net.TCPListener, error) {
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

	bindAddr := net.JoinHostPort(address, strconv.Itoa(int(port)))
	listener, err = (&net.ListenConfig{
		Control: ControlFunc,
	}).Listen(context.Background(),
		"tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err = (&net.ListenConfig{
		Control: ControlFunc,
	}).ListenPacket(context.Background(),
		"udp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}

// Set the socket options needed for tranparent proxying for the listening socket
// IP_TRANSPARENT allows socket to receive packets with any destination address/port
// IP_RECVORIGDSTADDR tells the kernel to pass the original destination address/port on recvmsg
// The socket may be receiving both IPv4 and IPv6 data, so set both options, if enabled.
func transparentSetsockopt(fd int) error {
	var err error
	err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err == nil {
		err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	}
	if err != nil {
		return err
	}
	return nil
}
