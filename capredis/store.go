// Package capredis provides a Redis-backed capgo.Store for multi-replica
// deployments. All single-use operations are executed as Lua scripts so
// they are atomic across instances.
package capredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zwh20081/capgo"
)

// Client is the subset of go-redis used by Store. Both *redis.Client and
// *redis.ClusterClient satisfy it.
type Client interface {
	redis.Scripter
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	SetArgs(ctx context.Context, key string, value any, a redis.SetArgs) *redis.StatusCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// Store implements capgo.Store on Redis.
type Store struct {
	client Client
	prefix string
}

// Option configures a Store.
type Option func(*Store)

// WithPrefix sets the key prefix (default "cap:").
func WithPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// New returns a Store using the given client.
func New(client Client, opts ...Option) *Store {
	s := &Store{client: client, prefix: "cap:"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Store) challengeKey(token string) string { return s.prefix + "challenge:" + token }
func (s *Store) nonceKey(key string) string       { return s.prefix + "nonce:" + key }
func (s *Store) tokenKey(key string) string       { return s.prefix + "token:" + key }

func ttlFor(expires, now int64) time.Duration {
	ms := expires - now
	if ms < 1 {
		ms = 1
	}
	return time.Duration(ms) * time.Millisecond
}

// takeChallenge: GET + DEL atomically.
var takeChallengeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
redis.call('DEL', KEYS[1])
return v
`)

// consumeToken: read, check scope, optionally delete.
var consumeTokenScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
local rec = cjson.decode(v)
if ARGV[1] ~= '' and (rec.scope or '') ~= ARGV[1] then return false end
if tonumber(rec.expires) <= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return false
end
if ARGV[3] == '0' then redis.call('DEL', KEYS[1]) end
return v
`)

func (s *Store) PutChallenge(ctx context.Context, token string, record capgo.ChallengeRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.challengeKey(token), data, ttlFor(record.Expires, time.Now().UnixMilli())).Err()
}

func (s *Store) TakeChallenge(ctx context.Context, token string, now int64) (capgo.ChallengeRecord, bool, error) {
	raw, err := takeChallengeScript.Run(ctx, s.client, []string{s.challengeKey(token)}).Result()
	if errors.Is(err, redis.Nil) {
		return capgo.ChallengeRecord{}, false, nil
	}
	if err != nil {
		return capgo.ChallengeRecord{}, false, err
	}
	text, ok := raw.(string)
	if !ok {
		return capgo.ChallengeRecord{}, false, nil
	}
	var record capgo.ChallengeRecord
	if err := json.Unmarshal([]byte(text), &record); err != nil {
		return capgo.ChallengeRecord{}, false, fmt.Errorf("capredis: corrupt challenge record: %w", err)
	}
	if record.Expires <= now {
		return capgo.ChallengeRecord{}, false, nil
	}
	return record, true, nil
}

func (s *Store) ClaimNonce(ctx context.Context, key string, expiresAt, now int64) (bool, error) {
	ttl := ttlFor(expiresAt, now)
	result, err := s.client.SetArgs(ctx, s.nonceKey(key), expiresAt, redis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return result == "OK", nil
}

func (s *Store) PutToken(ctx context.Context, key string, record capgo.TokenRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.tokenKey(key), data, ttlFor(record.Expires, time.Now().UnixMilli())).Err()
}

func (s *Store) ConsumeToken(ctx context.Context, key, scope string, now int64, keep bool) (capgo.TokenRecord, bool, error) {
	keepArg := "0"
	if keep {
		keepArg = "1"
	}
	raw, err := consumeTokenScript.Run(ctx, s.client, []string{s.tokenKey(key)}, scope, now, keepArg).Result()
	if errors.Is(err, redis.Nil) {
		return capgo.TokenRecord{}, false, nil
	}
	if err != nil {
		return capgo.TokenRecord{}, false, err
	}
	text, ok := raw.(string)
	if !ok {
		return capgo.TokenRecord{}, false, nil
	}
	var record capgo.TokenRecord
	if err := json.Unmarshal([]byte(text), &record); err != nil {
		return capgo.TokenRecord{}, false, fmt.Errorf("capredis: corrupt token record: %w", err)
	}
	return record, true, nil
}

// Cleanup is a no-op: every key carries a TTL.
func (s *Store) Cleanup(context.Context, int64) error { return nil }

// Reset deletes every key under the prefix using SCAN, so it is safe on
// shared instances but may take a while on very large keyspaces. Keys are
// deleted one at a time so it also works on Redis Cluster.
func (s *Store) Reset(ctx context.Context) error {
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, s.prefix+"*", 500).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := s.client.Del(ctx, key).Err(); err != nil {
				return err
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

var _ capgo.Store = (*Store)(nil)
