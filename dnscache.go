package dnscache

import (
	"time"

	"github.com/miekg/dns"
)

// Cache provides a proactive and expiring caching layer for DNS queries.
// All public methods of Cache are threadsafe.
type Cache struct {
	requestChan    chan Request
	responseChan   chan response
	expirationChan chan cacheKey
	clearChan      chan struct{}
	cacheMaxTTL    time.Duration
	cacheMissTTL   time.Duration
	lookup         func(dns.Question) []dns.RR
}

// Request defines a DNS request to be processed by a Cache object
type Request struct {
	Question     dns.Question
	ResponseChan chan []dns.RR
}

// New creates a DNS cache with the given DNS lookup function
func New(cacheMaxTTL, cacheMissTTL time.Duration, lookup func(dns.Question) []dns.RR) *Cache {
	c := &Cache{
		requestChan:    make(chan Request),
		responseChan:   make(chan response),
		expirationChan: make(chan cacheKey),
		clearChan:      make(chan struct{}),
		cacheMaxTTL:    cacheMaxTTL,
		cacheMissTTL:   cacheMissTTL,
		lookup:         lookup,
	}
	go c.process()
	return c
}

// Lookup will retrieve an answer for the given request from the cache if it
// is present and unexpired, otherwise it will attempt to retrieve the value via
// the cache's lookup function and cache the returned value
func (c *Cache) Lookup(r Request) {
	c.requestChan <- r
}

// Insert will insert the given resource records into the cache as a response
// to the given question
func (c *Cache) Insert(q dns.Question, rr []dns.RR) {
	c.responseChan <- response{Key: cacheKey{q}, RR: rr}
}

// Expire will remove any answers to the given question from the cache
func (c *Cache) Expire(q dns.Question) {
	c.expirationChan <- cacheKey{q}
}

// Clear will remove all recorded answers from the cache
func (c *Cache) Clear() {
	c.clearChan <- struct{}{}
}

type response struct {
	Key cacheKey
	RR  []dns.RR
}

type cacheKey struct {
	dns.Question
}

type cacheValue struct {
	Expiration time.Time
	Creation   time.Time
	HitCount   uint
	Timer      *time.Timer
	RR         []dns.RR
}

func (c *Cache) process() {
	data := make(map[cacheKey]*cacheValue)
	pending := make(map[cacheKey][]Request)

	for {
		select {
		case req := <-c.requestChan:
			key := cacheKey{req.Question}
			now := time.Now()
			if entry, ok := data[key]; ok && entry.Expiration.After(now) {
				elapsed := now.Sub(entry.Creation)
				entry.HitCount++
				if entry.HitCount == 1 {
					// This is the first cache hit since this entry was last updated
					// Update the timer so that it will proactively refresh the cache
					duration := entry.Expiration.Sub(entry.Creation)
					refresh := cacheRefreshDuration(duration, elapsed)
					entry.Timer.Reset(refresh)
				}
				rr := cacheCopy(entry.RR)
				cacheElapse(rr, uint32(elapsed/time.Second))
				//fmt.Printf("DNSCACHE HIT:         \t%v\t#%d\n", key, entry.HitCount)
				req.ResponseChan <- rr
			} else {
				if ok {
					//fmt.Printf("DNSCACHE EXPIRED: %v\n", key)
				} else {
					//fmt.Printf("DNSCACHE MISS: %v\n", key)
				}
				requests, running := pending[key]
				pending[key] = append(requests, req)
				if !running {
					go func() {
						rr := c.lookup(key.Question)
						c.responseChan <- response{Key: key, RR: rr}
					}()
				}
			}
		case resp := <-c.responseChan:
			key := resp.Key
			now := time.Now()
			duration := cacheDuration(resp.RR, c.cacheMaxTTL, c.cacheMissTTL)
			if duration > 0 {
				if entry, ok := data[key]; ok {
					entry.Expiration = now.Add(duration)
					entry.Creation = now
					entry.HitCount = 0
					entry.Timer.Reset(duration)
					entry.RR = resp.RR
				} else {
					data[key] = &cacheValue{
						Expiration: now.Add(duration),
						Creation:   now,
						HitCount:   0,
						Timer: time.AfterFunc(duration, func() {
							c.expirationChan <- key
						}),
						RR: resp.RR,
					}
				}
			}
			requests := pending[key]
			delete(pending, key)
			for _, req := range requests {
				req.ResponseChan <- cacheCopy(resp.RR)
			}
		case key := <-c.expirationChan:
			now := time.Now()
			if entry, ok := data[key]; ok {
				if entry.Expiration.After(now) {
					entry.Timer.Stop()
					delete(data, key)
				} else {
					entry.Timer.Reset(entry.Expiration.Sub(now))
				}
				if entry.HitCount > 0 {
					_, running := pending[key]
					if !running {
						pending[key] = make([]Request, 0)
						go func() {
							rr := c.lookup(key.Question)
							c.responseChan <- response{Key: key, RR: rr}
						}()
					}
				}
			}
		case <-c.clearChan:
			for _, entry := range data {
				entry.Timer.Stop()
			}
			data = make(map[cacheKey]*cacheValue)
		}
	}
}

// cacheCopy performs a deep copy of the given resource records
func cacheCopy(rr []dns.RR) []dns.RR {
	clone := make([]dns.RR, len(rr))
	for i := range rr {
		clone[i] = dns.Copy(rr[i])
	}
	return clone
}

// cacheElapse subtracts the given number of seconds from the TTL of each
// resource record provided
func cacheElapse(rr []dns.RR, seconds uint32) {
	for i := range rr {
		hdr := rr[i].Header()
		if seconds < hdr.Ttl {
			hdr.Ttl -= seconds
		} else {
			hdr.Ttl = 0
		}
	}
}

// cacheDuration determines how long an entry should be cached
func cacheDuration(rr []dns.RR, max time.Duration, empty time.Duration) time.Duration {
	if len(rr) == 0 {
		if max < empty {
			return max
		}
		return empty
	}
	ttl := rr[0].Header().Ttl
	for i := 1; i < len(rr); i++ {
		hdr := rr[i].Header()
		if hdr.Ttl < ttl {
			ttl = hdr.Ttl
		}
	}
	duration := time.Second * time.Duration(ttl)
	if duration > max {
		return max
	}
	return duration
}

// cacheRefreshDuration determines how long to wait until a cache refresh should occur
func cacheRefreshDuration(duration, elapsed time.Duration) time.Duration {
	remaining := duration - elapsed
	if remaining >= time.Second {
		return remaining / 2
	}
	return remaining
}
