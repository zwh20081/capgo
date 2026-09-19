package capgo

import (
	"context"
	"errors"
	"testing"
)

type failingStore struct{ MemoryStore }

func (f *failingStore) ClaimNonce(context.Context, string, int64, int64) (bool, error) {
	return false, errors.New("redis down")
}

func TestStoreFailureIsDistinguishable(t *testing.T) {
	fs := &failingStore{}
	_ = fs.Reset(context.Background())
	c := newTestCap(t, func(o *Options) { o.Stateless = true; o.Store = fs })
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	sol, _ := SolveChallenge(ch)
	_, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: sol}, RedeemOptions{})
	if !errors.Is(err, ErrStore) || ReasonOf(err) != ReasonNonceStoreError {
		t.Fatalf("err = %v", err)
	}
	var pe *Error
	if !errors.As(err, &pe) || pe.Cause == nil {
		t.Fatal("cause missing")
	}
}
