package auth

import (
	"container/list"
	"crypto/sha512"
	"encoding/hex"
	"sync"
	"time"
)

// resultCache caches the *result* of a successful OIDC bearer verification,
// keyed by a hash of the token, so repeat requests bearing the exact same
// token (the common case -- one CI job making many API calls with one token)
// skip signature verification, discovery, and JWKS lookups entirely. Safe
// because a JWT's payload is exactly the bytes that were signed: a
// byte-identical token can't have had any claim changed, so nothing about it
// needs re-checking except "is it still within its validity window."
type resultCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	entries map[string]*list.Element // key: sha512(token) hex
	order   *list.List               // front = most recently used
}

type cacheEntry struct {
	key       string
	identity  Identity
	expiresAt time.Time
}

func newResultCache(ttl time.Duration, maxSize int) *resultCache {
	return &resultCache{
		ttl:     ttl,
		maxSize: maxSize,
		entries: map[string]*list.Element{},
		order:   list.New(),
	}
}

func hashToken(token string) string {
	sum := sha512.Sum512([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (c *resultCache) get(token string) (Identity, bool) {
	key := hashToken(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return Identity{}, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(el)
		delete(c.entries, key)
		return Identity{}, false
	}
	c.order.MoveToFront(el)
	return entry.identity, true
}

// set caches identity for token, expiring no later than tokenExpiresAt (the
// token's own `exp` claim) regardless of how long c.ttl is -- a cache is a
// performance shortcut, not a way to extend a token's validity past what it
// was issued for.
func (c *resultCache) set(token string, identity Identity, tokenExpiresAt time.Time) {
	now := time.Now()
	expiresAt := now.Add(c.ttl)
	if tokenExpiresAt.Before(expiresAt) {
		expiresAt = tokenExpiresAt
	}
	if !expiresAt.After(now) {
		return // already expired, or expiring immediately -- not worth caching
	}

	key := hashToken(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.order.Remove(el)
		delete(c.entries, key)
	}
	el := c.order.PushFront(&cacheEntry{key: key, identity: identity, expiresAt: expiresAt})
	c.entries[key] = el
	for c.order.Len() > c.maxSize {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.entries, back.Value.(*cacheEntry).key)
	}
}
