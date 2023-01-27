package wildcard

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type StorageVersion string

const StorageVersionV1 = "v1"

type StorageConfig struct {
	Version       StorageVersion
	WildcardData  map[string]map[string]map[uint32]uint32 `json:"wildcardData"`
	WildcardIndex map[uint32]map[string]map[string]uint32 `json:"wildcardIndex"`
}

// Restore tries to restore the state from disk and logs errors on the way
func (c *Cache) Restore() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheFile := filepath.Join(c.storagePath, StorageFilename)
	c.log.Debugf("trying to restore wildcard index from %s", cacheFile)
	wcBytes, err := os.ReadFile(cacheFile)
	if err != nil {
		c.log.Infof("could not read cache file: %s", err.Error())
		return
	}

	sc := &StorageConfig{
		Version:       StorageVersionV1,
		WildcardData:  make(map[string]map[string]map[uint32]uint32),
		WildcardIndex: make(map[uint32]map[string]map[string]uint32),
	}

	err = json.Unmarshal(wcBytes, sc)
	if err != nil {
		c.log.Errorf("cache could not be decoded: %s", err.Error())
		return
	}
	c.log.Debugf("restored cache: %#v", sc)
	for k, v := range sc.WildcardData {
		c.wildcardData.Set(k, v, 0)
	}

	for k, v := range sc.WildcardIndex {
		c.wildcardIdx.Set(k, v, 0)
	}
	c.log.Debugf("restored wildcard index")
}

// Save flushes the internal state to disk
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sc := &StorageConfig{
		Version:       StorageVersionV1,
		WildcardData:  make(map[string]map[string]map[uint32]uint32),
		WildcardIndex: make(map[uint32]map[string]map[string]uint32),
	}

	for _, key := range c.wildcardData.Keys() {
		data, ok := c.wildcardData.Get(key)
		if !ok {
			continue
		}
		sc.WildcardData[key] = data
	}

	for _, key := range c.wildcardIdx.Keys() {
		data, ok := c.wildcardIdx.Get(key)
		if !ok {
			continue
		}
		sc.WildcardIndex[key] = data
	}

	wcBytes, err := json.Marshal(sc)
	if err != nil {
		return err
	}

	cacheFile := filepath.Join(c.storagePath, StorageFilename)
	c.log.Debugf("writing wildcard index to %s", cacheFile)
	err = os.MkdirAll(c.storagePath, os.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(cacheFile, wcBytes, os.ModePerm)
}
