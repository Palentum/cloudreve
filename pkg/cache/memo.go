package cache

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

const (
	hmacSize = sha256.Size
)

// MemoStore 内存存储驱动
type MemoStore struct {
	Store *sync.Map
}

// item 存储的对象
type itemWithTTL struct {
	Expires int64
	Value   interface{}
}

const DefaultCacheFile = "cache_persist.bin"

func newItem(value interface{}, expires int) itemWithTTL {
	expires64 := int64(expires)
	if expires > 0 {
		expires64 = time.Now().Unix() + expires64
	}
	return itemWithTTL{
		Value:   value,
		Expires: expires64,
	}
}

// getValue 从itemWithTTL中取值
func getValue(item interface{}, ok bool) (interface{}, bool) {
	if !ok {
		return nil, ok
	}

	var itemObj itemWithTTL
	if itemObj, ok = item.(itemWithTTL); !ok {
		return item, true
	}

	if itemObj.Expires > 0 && itemObj.Expires < time.Now().Unix() {
		return nil, false
	}

	return itemObj.Value, ok
}

// GarbageCollect 回收已过期的缓存
func (store *MemoStore) GarbageCollect() {
	store.Store.Range(func(key, value interface{}) bool {
		if item, ok := value.(itemWithTTL); ok {
			if item.Expires > 0 && item.Expires < time.Now().Unix() {
				store.Store.Delete(key)
			}
		}
		return true
	})
}

// NewMemoStore 新建内存存储
func NewMemoStore() *MemoStore {
	return &MemoStore{
		Store: &sync.Map{},
	}
}

// Set 存储值
func (store *MemoStore) Set(key string, value interface{}, ttl int) error {
	store.Store.Store(key, newItem(value, ttl))
	return nil
}

// Get 取值
func (store *MemoStore) Get(key string) (interface{}, bool) {
	return getValue(store.Store.Load(key))
}

// Gets 批量取值
func (store *MemoStore) Gets(keys []string, prefix string) (map[string]interface{}, []string) {
	res := make(map[string]interface{})
	var missed []string
	for _, key := range keys {
		fullKey := prefix + key
		if val, ok := store.Get(fullKey); ok {
			res[key] = val
		} else {
			missed = append(missed, key)
		}
	}
	return res, missed
}

// Sets 批量设置值
func (store *MemoStore) Sets(values map[string]interface{}, prefix string) error {
	for k, v := range values {
		store.Set(prefix+k, v, 0)
	}
	return nil
}

// Delete 批量删除值
func (store *MemoStore) Delete(keys []string, prefix string) error {
	for _, key := range keys {
		store.Store.Delete(prefix + key)
	}
	return nil
}

// cacheHMACKey 返回用于缓存完整性校验的 HMAC 密钥
func cacheHMACKey() []byte {
	return []byte(conf.SystemConfig.HashIDSalt)
}

// Persist write memory store into cache
func (store *MemoStore) Persist(path string) error {
	persisted := make(map[string]itemWithTTL)
	store.Store.Range(func(key, value interface{}) bool {
		v, ok := store.Store.Load(key)
		if _, ok := getValue(v, ok); ok {
			persisted[key.(string)] = v.(itemWithTTL)
		}

		return true
	})

	res, err := serializer(persisted)
	if err != nil {
		return fmt.Errorf("failed to serialize cache: %s", err)
	}

	// 附加 HMAC-SHA256 完整性校验
	mac := hmac.New(sha256.New, cacheHMACKey())
	mac.Write(res)
	expectedMAC := mac.Sum(nil)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %s", err)
	}
	defer f.Close()

	// 写入 HMAC + 数据
	if _, err := f.Write(expectedMAC); err != nil {
		return fmt.Errorf("failed to write cache HMAC: %s", err)
	}
	if _, err := f.Write(res); err != nil {
		return fmt.Errorf("failed to write cache data: %s", err)
	}

	return nil
}

// Restore memory cache from disk file
func (store *MemoStore) Restore(path string) error {
	if !util.Exists(path) {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %s", err)
	}

	defer func() {
		f.Close()
		os.Remove(path)
	}()

	// 读取 HMAC
	expectedMAC := make([]byte, hmacSize)
	if _, err := io.ReadFull(f, expectedMAC); err != nil {
		return fmt.Errorf("failed to read cache HMAC: %s", err)
	}

	// 读取数据
	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read cache data: %s", err)
	}

	// 验证 HMAC
	mac := hmac.New(sha256.New, cacheHMACKey())
	mac.Write(data)
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return fmt.Errorf("cache file integrity check failed")
	}

	persisted := &item{}
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&persisted); err != nil {
		return fmt.Errorf("unknown cache file format: %s", err)
	}

	items := persisted.Value.(map[string]itemWithTTL)
	loaded := 0
	for k, v := range items {
		if _, ok := getValue(v, true); ok {
			loaded++
			store.Store.Store(k, v)
		} else {
			util.Log().Debug("Persisted cache %q is expired.", k)
		}
	}

	util.Log().Info("Restored %d items from %q into memory cache.", loaded, path)
	return nil
}
