package regex

import (
	"context"
	"sync"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/sirupsen/logrus"
)

const (
	MaxKeys         = 8192
	StorageFilename = "wildcards.json"
)

type Cache struct {
	log         logrus.FieldLogger
	storagePath string

	// we need to synchronize both caches
	// otherwise we may end up in an inconsistent state
	mu *sync.Mutex

	// Stores a hierarchy of hostnames and maps them to an address
	//
	// *.foo.example.com -> map[actual.foo.example.com] => address
	wildcardData cache.Cache[string, map[string]map[uint32]uint32]

	// Stores an index of ips that map to hostnames
	// This allows us to lookup existing IPs from bpf maps
	// to see if they're still valid or need to be dropped
	wildcardIdx cache.Cache[uint32, map[string]map[string]uint32]
}

func New(log logrus.FieldLogger, storagePath string) *Cache {
	c := &Cache{
		log:         log,
		storagePath: storagePath,
		mu:          &sync.Mutex{},
		wildcardData: cache.NewCache[string, map[string]map[uint32]uint32]().
			WithMaxKeys(MaxKeys).
			WithLRU(),
		wildcardIdx: cache.NewCache[uint32, map[string]map[string]uint32]().
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
				c.log.Errorf("unable to save wildcard cache: %s", err.Error())
			}
		}
	}
}
