package providerusage

import (
	"sync"
	"time"
)

// Cache TTLs. Successful results are cached briefly to protect upstream quota
// endpoints; failures are cached only very briefly to avoid hammering an
// already-failing upstream. Errors are never cached longer than failureTTL so
// a transient problem self-corrects quickly.
const (
	defaultSuccessTTL = 45 * time.Second
	defaultFailureTTL = 10 * time.Second
)

// cacheEntry is a stored Result plus its expiry.
type cacheEntry struct {
	result    *Result
	expiresAt time.Time
}

// usageCache is a small, concurrency-safe TTL cache keyed by stable provider ID.
// It is intentionally in-process; no external cache is used.
type usageCache struct {
	mu          sync.RWMutex
	entries     map[string]cacheEntry
	successTTL  time.Duration
	failureTTL  time.Duration
	cleanupOnce sync.Once
}

func newUsageCache() *usageCache {
	c := &usageCache{
		entries:    make(map[string]cacheEntry),
		successTTL: defaultSuccessTTL,
		failureTTL: defaultFailureTTL,
	}
	c.cleanupOnce.Do(func() {
		go c.gcLoop()
	})
	return c
}

func resultIsSuccess(r *Result) bool {
	return r != nil && r.Error == nil && r.Usage != nil && r.HTTPStatus == httpStatusOK
}

// get returns a non-expired cached result for the key, if any.
func (c *usageCache) get(key string, now time.Time) (*Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.Before(e.expiresAt) {
		return e.result, true
	}
	return nil, false
}

// set stores a result, choosing the TTL based on success/failure. A fresh
// success always overwrites a prior failure; a failure does not overwrite a
// still-fresh success (the prior good value simply remains valid until its own
// TTL elapses).
func (c *usageCache) set(key string, res *Result, now time.Time) {
	if res == nil {
		return
	}
	success := resultIsSuccess(res)
	ttl := c.failureTTL
	if success {
		ttl = c.successTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !success {
		if prev, ok := c.entries[key]; ok && resultIsSuccess(prev.result) && now.Before(prev.expiresAt) {
			return
		}
	}
	c.entries[key] = cacheEntry{result: res, expiresAt: now.Add(ttl)}
}

func (c *usageCache) invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// flush clears all entries; intended for tests.
func (c *usageCache) flush() {
	c.mu.Lock()
	c.entries = make(map[string]cacheEntry)
	c.mu.Unlock()
}

func (c *usageCache) gcLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.gc(time.Now())
	}
}

func (c *usageCache) gc(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, key)
		}
	}
}
