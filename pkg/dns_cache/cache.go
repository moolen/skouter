package cache

import (
	"time"

	cache "github.com/go-pkgz/expirable-cache/v2"
	"github.com/sirupsen/logrus"
)

type Cache struct {
	log logrus.FieldLogger

	// hostnameData is used to lookup hostname -> ip address
	hostnameData cache.Cache[string, map[uint32]struct{}]
}

const (
	MaxKeys    = 8192
	DefaultTTL = time.Minute * 5
)

func New(log logrus.FieldLogger) *Cache {
	return &Cache{
		log: log,
		hostnameData: cache.NewCache[string, map[uint32]struct{}]().
			WithMaxKeys(MaxKeys).
			WithLRU().
			WithTTL(DefaultTTL),
	}
}
