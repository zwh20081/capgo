package capgo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

func TestInstrumentationGeneratorRoundTrip(t *testing.T) {
	for _, mode := range []string{"stored", "signed", "format2", "format2-explicit"} {
		t.Run(mode, func(t *testing.T) {
			now := time.UnixMilli(100000)
			type contextKey struct{}
			ctx := context.WithValue(context.Background(), contextKey{}, "request")
			calls := 0
			meta := InstrumentationMeta{ID: "custom", Vars: []string{"answer"}, ExpectedVals: []int32{42}, BlockAutomatedBrowsers: true}
			c := newTestCap(t, func(o *Options) {
				o.Now = func() time.Time { return now }
				o.Stateless = mode == "signed"
				o.Instrumentation = &InstrumentationOptions{BlockAutomatedBrowsers: true, ObfuscationLevel: 9}
				if mode == "format2" || mode == "format2-explicit" {
					o.Format = 2
					o.Protocols = []Protocol{ProtocolSHA256PoW}
				}
				if mode == "format2-explicit" {
					o.Protocols = []Protocol{ProtocolInstrumentation}
				}
				o.InstrumentationGenerator = func(gctx context.Context, random io.Reader, opts InstrumentationOptions, at time.Time) (*Instrumentation, error) {
					calls++
					if gctx.Value(contextKey{}) != "request" || random == nil || !at.Equal(now) || opts.TTL != time.Minute || opts.ObfuscationLevel != 9 || !opts.BlockAutomatedBrowsers {
						t.Fatalf("generator inputs: %+v, %v", opts, at)
					}
					return &Instrumentation{Blob: "custom-script", Meta: meta}, nil
				}
			})
			ch, err := c.Challenge(ctx, ChallengeOptions{Scope: "login", ChallengeTTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("generator called %d times", calls)
			}
			result := goodInstrResult(&meta)
			// A reused generator buffer must not change stored verification state.
			meta.ExpectedVals[0] = 99
			meta.Vars[0] = "changed"
			req := RedeemRequest{Token: ch.Token}
			if ch.Format == 2 {
				var solutions []any
				for _, entry := range ch.Challenges {
					switch p := entry.Payload.(type) {
					case PoWPayload:
						solutions = append(solutions, map[string]any{"nonce": SolvePoW(p.Salt, p.Target)})
					case InstrumentationPayload:
						if p.Blob != "custom-script" {
							t.Fatal("custom blob not returned")
						}
						solutions = append(solutions, map[string]any{"instr": result})
					}
				}
				req.Solutions, _ = json.Marshal(solutions)
			} else {
				if ch.Instrumentation != "custom-script" {
					t.Fatal("custom blob not returned")
				}
				req.Solutions, err = SolveChallenge(ch)
				if err != nil {
					t.Fatal(err)
				}
				req.Instr = result
			}
			token, err := c.Redeem(ctx, req, RedeemOptions{Scope: "login"})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []bool{true, false} {
				ok, err := c.Validate(ctx, token.Token, ValidateOptions{Scope: "login"})
				if err != nil || ok != want {
					t.Fatalf("Validate = %v, %v; want %v", ok, err, want)
				}
			}
		})
	}
}

func TestInstrumentationGeneratorSelection(t *testing.T) {
	globalCalls, overrideCalls := 0, 0
	makeGenerator := func(calls *int) InstrumentationGenerator {
		return func(_ context.Context, _ io.Reader, _ InstrumentationOptions, _ time.Time) (*Instrumentation, error) {
			*calls++
			return &Instrumentation{Blob: "blob", Meta: InstrumentationMeta{ID: "id", Vars: []string{"a"}, ExpectedVals: []int32{1}}}, nil
		}
	}
	c := newTestCap(t, func(o *Options) {
		o.Instrumentation = &InstrumentationOptions{}
		o.InstrumentationGenerator = makeGenerator(&globalCalls)
	})
	for _, opts := range []ChallengeOptions{
		{},
		{InstrumentationGenerator: makeGenerator(&overrideCalls)},
		{DisableInstrumentation: true, InstrumentationGenerator: makeGenerator(&overrideCalls)},
	} {
		if _, err := c.Challenge(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	}
	if globalCalls != 1 || overrideCalls != 1 {
		t.Fatalf("calls: global=%d override=%d", globalCalls, overrideCalls)
	}
	// An explicitly selected format-2 instrumentation protocol needs no options.
	c = newTestCap(t, func(o *Options) {
		o.Format = 2
		o.Protocols = []Protocol{ProtocolInstrumentation}
		o.InstrumentationGenerator = makeGenerator(&globalCalls)
	})
	if _, err := c.Challenge(context.Background(), ChallengeOptions{}); err != nil || globalCalls != 2 {
		t.Fatalf("explicit protocol: calls=%d err=%v", globalCalls, err)
	}
}

func TestInstrumentationGeneratorFailures(t *testing.T) {
	failure := errors.New("generator unavailable")
	for _, mode := range []string{"stored", "signed", "format2"} {
		for _, scenario := range []string{"error", "nil", "missing blob", "missing id", "empty vars", "mismatched vars", "duplicate vars", "empty name", "changed policy", "canceled", "canceled during generation"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				c := newTestCap(t, func(o *Options) {
					o.Stateless = mode == "signed"
					if mode == "format2" {
						o.Format = 2
						o.Protocols = []Protocol{ProtocolInstrumentation}
					}
					o.Instrumentation = &InstrumentationOptions{}
					o.InstrumentationGenerator = func(context.Context, io.Reader, InstrumentationOptions, time.Time) (*Instrumentation, error) {
						calls++
						result := &Instrumentation{Blob: "blob", Meta: InstrumentationMeta{ID: "id", Vars: []string{"a"}, ExpectedVals: []int32{1}}}
						switch scenario {
						case "error":
							return nil, failure
						case "nil":
							return nil, nil
						case "missing blob":
							result.Blob = ""
						case "missing id":
							result.Meta.ID = ""
						case "empty vars":
							result.Meta.Vars = nil
						case "mismatched vars":
							result.Meta.ExpectedVals = nil
						case "duplicate vars":
							result.Meta.Vars = []string{"a", "a"}
							result.Meta.ExpectedVals = []int32{1, 1}
						case "empty name":
							result.Meta.Vars[0] = ""
						case "changed policy":
							result.Meta.BlockAutomatedBrowsers = true
						case "canceled during generation":
							cancel()
						}
						return result, nil
					}
				})
				want := ErrConfig
				if scenario == "error" {
					want = failure
				}
				if scenario == "canceled" {
					cancel()
				}
				if scenario == "canceled" || scenario == "canceled during generation" {
					want = context.Canceled
				}
				if ch, err := c.Challenge(ctx, ChallengeOptions{}); ch != nil || !errors.Is(err, want) {
					t.Fatalf("Challenge = %v, %v; want %v", ch, err, want)
				}
				if scenario == "canceled" && calls != 0 {
					t.Fatal("called generator on canceled context")
				}
				if len(c.Store().(*MemoryStore).challenges) != 0 {
					t.Fatal("failed generation stored a challenge")
				}
			})
		}
	}
}
