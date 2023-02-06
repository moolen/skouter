package util

import (
	"bytes"
	"encoding/binary"
	"net"
)

func ToHostBytes32(n uint32) []byte {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, n)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func ToHost16(n uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return binary.LittleEndian.Uint16(b)
}

func ToNetBytes16(n uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(n))
	return binary.BigEndian.Uint16(b)
}

func IPToUint(addr net.IP) uint32 {
	addr = addr.To4()
	if addr == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(addr)
}

func MaskToUint(mask net.IPMask) uint32 {
	return binary.LittleEndian.Uint32(mask)
}

func ToIP(addr uint32) net.IP {
	return net.IP(ToHostBytes32(addr))
}

func ToNetMask(addr, mask uint32) *net.IPNet {
	var buf []byte
	buf = append(buf, ToHostBytes32(mask)...)
	return &net.IPNet{
		IP:   ToIP(addr),
		Mask: net.IPMask(buf),
	}
}
