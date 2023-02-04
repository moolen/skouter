package fqdn

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type StorageVersion string

const StorageVersionV1 = "v1"

type StorageConfig struct {
	Version   StorageVersion
	FQDNData  map[string]map[string]map[uint32]uint32 `json:"fqdnData"`
	FQDNIndex map[uint32]map[string]map[string]uint32 `json:"fqdnIndex"`
}

// Restore tries to restore the state from disk and logs errors on the way
func (c *Cache) Restore() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheFile := filepath.Join(c.storagePath, StorageFilename)
	logger.Info("trying to restore fqdn index", "file", cacheFile)
	wcBytes, err := os.ReadFile(cacheFile)
	if err != nil {
		logger.Error(err, "could not read cache file")
		return
	}

	sc := &StorageConfig{
		Version:   StorageVersionV1,
		FQDNData:  make(map[string]map[string]map[uint32]uint32),
		FQDNIndex: make(map[uint32]map[string]map[string]uint32),
	}

	err = json.Unmarshal(wcBytes, sc)
	if err != nil {
		logger.Error(err, "cache could not be decoded")
		return
	}
	logger.Info("restored cache", "data", sc)
	for k, v := range sc.FQDNData {
		c.fqdnData.Set(k, v, 0)
	}

	for k, v := range sc.FQDNIndex {
		c.fqdnIdx.Set(k, v, 0)
	}
	logger.Info("restored fqdn index")
}

// Save flushes the internal state to disk
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sc := &StorageConfig{
		Version:   StorageVersionV1,
		FQDNData:  make(map[string]map[string]map[uint32]uint32),
		FQDNIndex: make(map[uint32]map[string]map[string]uint32),
	}

	for _, key := range c.fqdnData.Keys() {
		data, ok := c.fqdnData.Get(key)
		if !ok {
			continue
		}
		sc.FQDNData[key] = data
	}

	for _, key := range c.fqdnIdx.Keys() {
		data, ok := c.fqdnIdx.Get(key)
		if !ok {
			continue
		}
		sc.FQDNIndex[key] = data
	}

	wcBytes, err := json.Marshal(sc)
	if err != nil {
		return err
	}

	cacheFile := filepath.Join(c.storagePath, StorageFilename)
	err = os.MkdirAll(c.storagePath, os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFile, wcBytes, os.ModePerm)
}
