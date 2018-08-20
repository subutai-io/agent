package utils

import (
	"github.com/wunderlist/ttlcache"
	"time"
)

type Calculate func() string

func GetCache(ttl time.Duration) *ttlcache.Cache {
	return ttlcache.NewCache(ttl)
}

func GetFromCacheOrCalculate(cache *ttlcache.Cache, cacheKey string, calc Calculate) string {
	value, exists := cache.Get(cacheKey)

	if exists {
		return value
	} else {
		value = calc()
		if value != "" {
			cache.Set(cacheKey, value)
		}
		return value
	}
}
