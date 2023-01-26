package cache

import (
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/sirupsen/logrus"
)

type Cache struct {
	log logrus.FieldLogger

	// Stores a hierarchy of hostnames and maps them to an address
	//
	// *.foo.example.com -> map[actual.foo.example.com] => address
	wildcardData cache.Cache[string, map[string]map[uint32]uint32]

	// Stores an index of ips that map to hostnames
	// This allows us to lookup existing IPs from bpf maps
	// to see if they're still valid or need to be dropped
	wildcardIdx cache.Cache[uint32, map[string]map[string]uint32]
}

const (
	MaxKeys    = 8192
	DefaultTTL = time.Minute * 5
)

func New(log logrus.FieldLogger) *Cache {
	return &Cache{
		log: log,
		wildcardData: cache.NewCache[string, map[string]map[uint32]uint32]().
			WithMaxKeys(MaxKeys).
			WithLRU(),
		wildcardIdx: cache.NewCache[uint32, map[string]map[string]uint32]().
			WithMaxKeys(MaxKeys).
			WithLRU(),
	}
}
