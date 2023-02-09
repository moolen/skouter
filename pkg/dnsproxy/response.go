package dnsproxy

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

// this is a subset of the dns.ResponseWriter
type DNSResponseWriter interface {
	// LocalAddr returns the net.UDPAddr of the server
	LocalAddr() net.Addr
	// RemoteAddr returns the net.UDPAddr of the client that sent the current request.
	RemoteAddr() net.Addr
	// WriteMsg writes a reply back to the client.
	WriteMsg(*dns.Msg) error
}

// ResponseWriter satisfies the DNSResponseWriter interface
type ResponseWriter struct {
	conn       *net.IPConn
	localAddr  net.IP
	localPort  uint16
	remoteAddr net.IP
	remotePort uint16
}

func (r *ResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   r.localAddr,
		Port: int(r.localPort),
	}
}

func (r *ResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   r.remoteAddr,
		Port: int(r.remotePort),
	}
}

func (r *ResponseWriter) WriteMsg(msg *dns.Msg) error {
	payload, err := msg.Pack()
	if err != nil {
		return err
	}

	l := len(payload)
	bb := bytes.NewBuffer(nil)
	_ = binary.Write(bb, binary.BigEndian, uint16(r.remotePort))
	_ = binary.Write(bb, binary.BigEndian, uint16(r.localPort))
	_ = binary.Write(bb, binary.BigEndian, uint16(8+l))
	_ = binary.Write(bb, binary.BigEndian, uint16(0)) // checksum
	_, _ = bb.Write(payload)
	buf := bb.Bytes()

	cm := new(ipv4.ControlMessage)
	cm.Src = r.remoteAddr
	_, _, err = r.conn.WriteMsgIP(buf, cm.Marshal(), &net.IPAddr{
		IP: r.localAddr,
	})
	return err
}
