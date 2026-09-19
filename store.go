package capgo

import (
	"context"
	"errors"
	"sync"
)

// ChallengeRecord is the server-side state of a stateful (format 1, stored)
// challenge, mirroring @cap.js/server's challengesList entries.
type ChallengeRecord struct {
	Count      int                  `json:"c"`
	Size       int                  `json:"s"`
	Difficulty int                  `json:"d"`
	Scope      string               `json:"scope,omitempty"`
	Expires    int64                `json:"expires"` // Unix milliseconds
	Instr      *InstrumentationMeta `json:"instr,omitempty"`
}

// TokenRecord is the server-side state of an issued verification token.
type TokenRecord struct {
	Scope   string `json:"scope,omitempty"`
	Expires int64  `json:"expires"` // Unix milliseconds
}

// Store persists the small amount of state Cap needs. Every method must be
// safe for concurrent use; TakeChallenge, ClaimNonce and ConsumeToken must be
// atomic so that a challenge, nonce or token can be used exactly once across
// all replicas sharing the store.
//
// All timestamps are Unix milliseconds. Implementations may drop expired
// entries eagerly (TTL) or lazily; callers always pass the current time.
type Store interface {
	// PutChallenge stores a stateful challenge under its token.
	PutChallenge(ctx context.Context, token string, record ChallengeRecord) error
	// TakeChallenge atomically fetches and deletes a stateful challenge.
	// It returns ok=false when the challenge is missing or expired.
	TakeChallenge(ctx context.Context, token string, now int64) (record ChallengeRecord, ok bool, err error)

	// ClaimNonce atomically marks key as used until expiresAt. It returns
	// false when the key was already claimed and has not expired.
	ClaimNonce(ctx context.Context, key string, expiresAt, now int64) (bool, error)

	// PutToken stores an issued verification token under its hashed key.
	PutToken(ctx context.Context, key string, record TokenRecord) error
	// ConsumeToken atomically looks up a verification token. If scope is
	// non-empty the stored scope must match, otherwise the token is left
	// untouched and ok=false is returned. When keep is false the token is
	// deleted on success.
	ConsumeToken(ctx context.Context, key, scope string, now int64, keep bool) (record TokenRecord, ok bool, err error)

	// Cleanup removes expired entries. Stores with native TTLs may no-op.
	Cleanup(ctx context.Context, now int64) error
	// Reset drops all state. Used when secrets are rotated.
	Reset(ctx context.Context) error
}

// ErrStore wraps storage failures so callers can distinguish them from
// protocol failures.
var ErrStore = errors.New("capgo: store error")

type memoryNonce struct{ expires int64 }

// MemoryStore is the default single-process Store. It never blocks and keeps
// everything in maps; call Cleanup periodically (Cap does so lazily).
type MemoryStore struct {
	mu         sync.Mutex
	challenges map[string]ChallengeRecord
	nonces     map[string]memoryNonce
	tokens     map[string]TokenRecord
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		challenges: map[string]ChallengeRecord{},
		nonces:     map[string]memoryNonce{},
		tokens:     map[string]TokenRecord{},
	}
}

func (s *MemoryStore) PutChallenge(_ context.Context, token string, record ChallengeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[token] = record
	return nil
}

func (s *MemoryStore) TakeChallenge(_ context.Context, token string, now int64) (ChallengeRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.challenges[token]
	if !ok {
		return ChallengeRecord{}, false, nil
	}
	delete(s.challenges, token)
	if record.Expires <= now {
		return ChallengeRecord{}, false, nil
	}
	return record, true, nil
}

func (s *MemoryStore) ClaimNonce(_ context.Context, key string, expiresAt, now int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.nonces[key]; ok && current.expires > now {
		return false, nil
	}
	s.nonces[key] = memoryNonce{expires: expiresAt}
	return true, nil
}

func (s *MemoryStore) PutToken(_ context.Context, key string, record TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[key] = record
	return nil
}

func (s *MemoryStore) ConsumeToken(_ context.Context, key, scope string, now int64, keep bool) (TokenRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tokens[key]
	if !ok {
		return TokenRecord{}, false, nil
	}
	if record.Expires <= now {
		delete(s.tokens, key)
		return TokenRecord{}, false, nil
	}
	if scope != "" && record.Scope != scope {
		return TokenRecord{}, false, nil
	}
	if !keep {
		delete(s.tokens, key)
	}
	return record, true, nil
}

func (s *MemoryStore) Cleanup(_ context.Context, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, record := range s.challenges {
		if record.Expires <= now {
			delete(s.challenges, key)
		}
	}
	for key, nonce := range s.nonces {
		if nonce.expires <= now {
			delete(s.nonces, key)
		}
	}
	for key, record := range s.tokens {
		if record.Expires <= now {
			delete(s.tokens, key)
		}
	}
	return nil
}

func (s *MemoryStore) Reset(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges = map[string]ChallengeRecord{}
	s.nonces = map[string]memoryNonce{}
	s.tokens = map[string]TokenRecord{}
	return nil
}

// Len reports the number of live entries; handy for tests and metrics.
func (s *MemoryStore) Len() (challenges, nonces, tokens int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.challenges), len(s.nonces), len(s.tokens)
}
