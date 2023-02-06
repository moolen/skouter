package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/moolen/skouter/pkg/log"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var logger = log.DefaultLogger

func main() {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second*5))
	defer cancel()
	receive(ctx)
}

func spoofpkg(msg dns.Msg) {
	c, err := net.DialIP("ip4:udp", &net.IPAddr{
		IP: net.ParseIP("127.0.100.100"),
	}, &net.IPAddr{
		IP: net.ParseIP("127.0.123.123"),
	})
	if err != nil {
		logger.Error(err, "unale to dial IP")
	}
	cp := msg.Copy()
	arec, ok := cp.Answer[0].(*dns.A)
	if !ok {
		logger.Error(err, "answer[0] not a a rec")
		return
	}
	arec.Header().Name = "aaa.aaa.aaa."
	msgBytes, err := cp.Pack()
	if err != nil {
		logger.Error(err, "unable to pack dns message")
		return
	}
	len := len(msgBytes)
	// 16bit src port
	// 16bit dst port
	// 16bit length
	// 16bit checksum
	udphdr := []byte{255, 255, 0, 0, 0, uint8(len), 0, 0}
	_, err = c.Write(append(udphdr, msgBytes...))
	if err != nil {
		logger.Error(err, "unable to write to connection")
	}
}

func receive(ctx context.Context) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	udpOffset := 28

	for {
		select {
		default:
			buf := make([]byte, 1024)
			numRead, err := f.Read(buf)
			if err != nil {
				logger.Error(err, "error read")
			}

			saddr := buf[12:16]
			daddr := buf[16:20]

			logger.Info("raw packet", "len", numRead, "saddr", net.IP(saddr), "daddr", net.IP(daddr), "packet", buf[:numRead])
			var msg dns.Msg
			err = msg.Unpack(buf[udpOffset:numRead])
			if err != nil {
				logger.Error(err, "unable to parse dns", "read", numRead, "packet", buf[udpOffset:numRead])
				continue
			}
			logger.Info("dns packet", "dns", msg)
			for _, a := range msg.Answer {
				arec, ok := a.(*dns.A)
				if !ok {
					continue
				}
				logger.Info("found A record", "name", arec.Header().Name, "address", arec.A.String())
				if arec.Header().Name == "github.com." {
					spoofpkg(msg)
				}
			}
		case <-ctx.Done():
			logger.Info("receive: context done")
			return
		}

	}
}
