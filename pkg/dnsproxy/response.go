package dnsproxy

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/miekg/dns"
	"github.com/moolen/skouter/pkg/bpf"
	"github.com/moolen/skouter/pkg/util"
	"golang.org/x/net/ipv4"
)

// this is a subset of the dns.ResponseWriter
type DNSResponseWriter interface {
	// LocalAddr returns the net.UDPAddr of the server
	LocalAddr() *net.UDPAddr
	// RemoteAddr returns the net.UDPAddr of the client that sent the current request.
	RemoteAddr() *net.UDPAddr
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

func resWriterfromEvent(conn *net.IPConn, ev *bpf.Event) *ResponseWriter {
	return &ResponseWriter{
		conn:       conn,
		localAddr:  util.ToIP(ev.PodAddr),
		localPort:  util.ToHost16(ev.PodPort),
		remoteAddr: util.ToIP(ev.DstAddr),
		remotePort: util.ToHost16(ev.DstPort),
	}
}

func (r *ResponseWriter) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   r.localAddr,
		Port: int(r.localPort),
	}
}

func (r *ResponseWriter) RemoteAddr() *net.UDPAddr {
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
