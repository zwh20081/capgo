package capredis_test

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zwh20081/capgo"
	"github.com/zwh20081/capgo/capredis"
)

func newStore(t *testing.T) (*capredis.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return capredis.New(client, capredis.WithPrefix("t:")), mr
}

func TestChallengeTakeIsSingleUse(t *testing.T) {
	store, mr := newStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	rec := capgo.ChallengeRecord{Count: 2, Size: 32, Difficulty: 1, Scope: "login", Expires: now + 60_000}
	if err := store.PutChallenge(ctx, "tok", rec); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL("t:challenge:tok"); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("ttl = %v", ttl)
	}
	got, ok, err := store.TakeChallenge(ctx, "tok", now)
	if err != nil || !ok || got != rec {
		t.Fatalf("take = %+v %v %v", got, ok, err)
	}
	if _, ok, _ := store.TakeChallenge(ctx, "tok", now); ok {
		t.Fatal("challenge taken twice")
	}
	_ = store.PutChallenge(ctx, "old", capgo.ChallengeRecord{Expires: now + 10})
	if _, ok, _ := store.TakeChallenge(ctx, "old", now+10); ok {
		t.Fatal("expired challenge returned")
	}
}

func TestNonceClaimOnce(t *testing.T) {
	store, mr := newStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	ok, err := store.ClaimNonce(ctx, "sig", now+5000, now)
	if err != nil || !ok {
		t.Fatalf("first claim = %v %v", ok, err)
	}
	if ok, _ := store.ClaimNonce(ctx, "sig", now+5000, now); ok {
		t.Fatal("nonce claimed twice")
	}
	mr.FastForward(6 * time.Second)
	if ok, _ := store.ClaimNonce(ctx, "sig", now+20000, now+6000); !ok {
		t.Fatal("expired nonce not reclaimable")
	}
}

func TestTokenScopeAndConsume(t *testing.T) {
	store, mr := newStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	if err := store.PutToken(ctx, "id:hash", capgo.TokenRecord{Scope: "login", Expires: now + 60_000}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.ConsumeToken(ctx, "id:hash", "signup", now, false); ok {
		t.Fatal("wrong scope accepted")
	}
	if rec, ok, _ := store.ConsumeToken(ctx, "id:hash", "login", now, true); !ok || rec.Scope != "login" {
		t.Fatalf("keep consume = %+v %v", rec, ok)
	}
	if _, ok, _ := store.ConsumeToken(ctx, "id:hash", "", now, false); !ok {
		t.Fatal("unscoped consume rejected")
	}
	if _, ok, _ := store.ConsumeToken(ctx, "id:hash", "", now, false); ok {
		t.Fatal("token consumed twice")
	}
	_ = store.PutToken(ctx, "exp", capgo.TokenRecord{Expires: now + 1000})
	if _, ok, _ := store.ConsumeToken(ctx, "exp", "", now+1000, false); ok {
		t.Fatal("expired token accepted")
	}
	if mr.Exists("t:token:exp") {
		t.Fatal("expired token not deleted")
	}
}

func TestResetOnlyTouchesPrefix(t *testing.T) {
	store, mr := newStore(t)
	ctx := context.Background()
	_ = mr.Set("other:key", "1")
	_ = store.PutToken(ctx, "a", capgo.TokenRecord{Expires: time.Now().UnixMilli() + 60_000})
	if err := store.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("t:token:a") || !mr.Exists("other:key") {
		t.Fatal("reset scope wrong")
	}
}

func TestEndToEndWithCap(t *testing.T) {
	store, _ := newStore(t)
	c, err := capgo.New(capgo.Options{Secret: bytes.Repeat([]byte{1}, 32), Store: store, ChallengeCount: 1, ChallengeDifficulty: 1, Stateless: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ch, err := c.Challenge(ctx, capgo.ChallengeOptions{Scope: "login"})
	if err != nil {
		t.Fatal(err)
	}
	solutions, _ := capgo.SolveChallenge(ch)
	// Two replicas redeem the same solved challenge concurrently: one wins.
	var wins atomic.Int32
	var wg sync.WaitGroup
	tokens := make(chan *capgo.Token, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.Redeem(ctx, capgo.RedeemRequest{Token: ch.Token, Solutions: solutions}, capgo.RedeemOptions{Scope: "login"})
			if err == nil {
				wins.Add(1)
				tokens <- tok
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("redeemed %d times", wins.Load())
	}
	tok := <-tokens
	var valid atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := c.Validate(ctx, tok.Token, capgo.ValidateOptions{Scope: "login"}); ok {
				valid.Add(1)
			}
		}()
	}
	wg.Wait()
	if valid.Load() != 1 {
		t.Fatalf("validated %d times", valid.Load())
	}
	// Stateful mode also works on Redis.
	c2, _ := capgo.New(capgo.Options{Store: store, ChallengeCount: 1, ChallengeDifficulty: 1})
	ch2, _ := c2.Challenge(ctx, capgo.ChallengeOptions{})
	sol2, _ := capgo.SolveChallenge(ch2)
	if _, err := c2.Redeem(ctx, capgo.RedeemRequest{Token: ch2.Token, Solutions: sol2}, capgo.RedeemOptions{}); err != nil {
		t.Fatal(err)
	}
}
