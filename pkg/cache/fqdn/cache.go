package fqdn

import (
	"context"
	"sync"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/moolen/skouter/pkg/log"
)

const (
	MaxKeys         = 8192
	StorageFilename = "fqdn.json"
)

var logger = log.DefaultLogger.WithName("fqdncache")

type Cache struct {
	storagePath string

	// we need to synchronize both caches
	// otherwise we may end up in an inconsistent state
	mu *sync.Mutex

	// Stores a hierarchy of hostnames and maps them to an address
	//
	// *.foo.example.com -> map[actual.foo.example.com] => address
	fqdnData cache.Cache[string, map[string]map[uint32]uint32]

	// Stores an index of ips that map to hostnames
	// This allows us to lookup existing IPs from bpf maps
	// to see if they're still valid or need to be dropped
	fqdnIdx cache.Cache[uint32, map[string]map[string]uint32]
}

func New(storagePath string) *Cache {
	c := &Cache{
		storagePath: storagePath,
		mu:          &sync.Mutex{},
		fqdnData: cache.NewCache[string, map[string]map[uint32]uint32]().
			WithMaxKeys(MaxKeys).
			WithLRU(),
		fqdnIdx: cache.NewCache[uint32, map[string]map[string]uint32]().
			WithMaxKeys(MaxKeys).
			WithLRU(),
	}

	return c
}

// periodically flush state to disk
func (c *Cache) Autosave(ctx context.Context, d time.Duration) {
	tt := time.NewTicker(d)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tt.C:
			err := c.Save()
			if err != nil {
				logger.Error(err, "unable to save fqdn cache: %s")
			}
		}
	}
}
