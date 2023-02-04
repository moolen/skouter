package cache

import (
	"context"
	"net"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/moolen/skouter/pkg/log"
	"github.com/moolen/skouter/pkg/sock"
)

type Cache struct {
	resolver *net.Resolver

	// hostnameData is used to lookup hostname -> ip address
	hostnameData cache.Cache[string, map[uint32]struct{}]
}

const (
	MaxKeys    = 8192
	DefaultTTL = time.Minute * 5
)

var logger = log.DefaultLogger.WithName("dnscache")

func New() *Cache {
	resolver := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: sock.ControlFunc,
			}
			return dialer.Dial(network, address)
		},
	}
	return &Cache{
		resolver: resolver,
		hostnameData: cache.NewCache[string, map[uint32]struct{}]().
			WithMaxKeys(MaxKeys).
			WithLRU().
			WithTTL(DefaultTTL),
	}
}
