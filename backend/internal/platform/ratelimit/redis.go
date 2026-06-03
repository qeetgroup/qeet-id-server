package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucket is an atomic token-bucket refill+consume in Lua, so a limit is
// enforced consistently across replicas in a single round-trip.
//
//	KEYS[1] = bucket key
//	ARGV    = rate (tokens/sec), capacity, now (unix ms)
//	returns = { allowed (0|1), retryAfterSeconds }
var tokenBucket = redis.NewScript(`
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end
local elapsed = math.max(0, now - ts) / 1000.0
tokens = math.min(capacity, tokens + elapsed * rate)
local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = math.ceil((1 - tokens) / rate)
  if retry < 1 then retry = 1 end
end
redis.call('HSET', key, 'tokens', tokens, 'ts', now)
local ttl = math.ceil(capacity / rate) + 1
if ttl < 60 then ttl = 60 end
redis.call('EXPIRE', key, ttl)
return { allowed, retry }
`)

type redisStore struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisStore returns a Store that shares token buckets across replicas via
// Redis. Pair it with NewWithStore.
func NewRedisStore(rdb redis.UniversalClient) Store {
	return &redisStore{rdb: rdb, prefix: "rl:"}
}

func (s *redisStore) Take(ctx context.Context, key string, rate, capacity float64) (bool, int, error) {
	now := time.Now().UnixMilli()
	res, err := tokenBucket.Run(ctx, s.rdb, []string{s.prefix + key}, rate, capacity, now).Int64Slice()
	if err != nil {
		return false, 0, err
	}
	if len(res) != 2 {
		return false, 0, nil
	}
	return res[0] == 1, int(res[1]), nil
}
