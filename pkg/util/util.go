package util

import (
	"bytes"
	"encoding/binary"
	"net"
)

func ToHostBytes(n uint32) []byte {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, n)
	if err != nil {
		return nil
	}
	return buf.Bytes()
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
	return net.IP(ToHostBytes(addr))
}

func ToNetMask(addr, mask uint32) net.IPMask {
	var buf []byte
	buf = append(buf, ToHostBytes(addr)...)
	buf = append(buf, ToHostBytes(mask)...)
	return net.IPMask(buf)
}
