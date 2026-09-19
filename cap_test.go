package capgo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	testKeypairOnce sync.Once
	testKeypair     *RSWKeypair
	testKeypairErr  error
)

func loadTestKeypair(t *testing.T) *RSWKeypair {
	t.Helper()
	testKeypairOnce.Do(func() {
		testKeypair, testKeypairErr = GenerateRSWKeypair(rand.Reader, 2048)
	})
	if testKeypairErr != nil {
		t.Fatal(testKeypairErr)
	}
	return testKeypair
}

var testSecret = bytes.Repeat([]byte{0x42}, 32)

func newTestCap(t *testing.T, mutate func(*Options)) *Cap {
	t.Helper()
	opts := Options{
		Secret:              testSecret,
		ChallengeCount:      2,
		ChallengeDifficulty: 1,
		RSWIterations:       2000,
	}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func solveAndRedeem(t *testing.T, c *Cap, ch *Challenge, scope string) *Token {
	t.Helper()
	solutions, err := SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	token, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// ---- PRNG compatibility ----

func TestPRNGMatchesJavaScript(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors.PRNG {
		if got := PRNG(v.Seed, v.Len); got != v.Out {
			t.Fatalf("PRNG(%q,%d) = %q want %q", v.Seed, v.Len, got, v.Out)
		}
	}
	// Resume form must equal the plain form.
	salt, target := format1Pair("tok", 3, 32, 4)
	if salt != PRNG("tok3", 32) || target != PRNG("tok3d", 4) {
		t.Fatal("format1Pair diverges from PRNG")
	}
}

type fixtureCase struct {
	SecretHex  string        `json:"secretHex"`
	Scope      string        `json:"scope"`
	ValidateAt int64         `json:"validateAt"`
	Challenge  Challenge     `json:"challenge"`
	RedeemBody RedeemRequest `json:"redeemBody"`
}

type vectorFile struct {
	PRNG []struct {
		Seed string `json:"seed"`
		Len  int    `json:"len"`
		Out  string `json:"out"`
	} `json:"prng"`
	Format1 fixtureCase `json:"format1"`
	Format2 fixtureCase `json:"format2pow"`
	Instr   struct {
		Meta       InstrumentationMeta `json:"meta"`
		GoodResult json.RawMessage     `json:"goodResult"`
		Blob       string              `json:"blob"`
	} `json:"instrumentation"`
	Format1Instr struct {
		fixtureCase
		MissingInstrReason string `json:"missingInstrReason"`
	} `json:"format1instr"`
	Format2Instr struct {
		fixtureCase
		BlockedReason string `json:"blockedReason"`
		TimeoutReason string `json:"timeoutReason"`
	} `json:"format2instr"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/capjs-core-0.1.1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func fixtureCap(t *testing.T, fc fixtureCase) *Cap {
	t.Helper()
	secret, err := hex.DecodeString(fc.SecretHex)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Secret: secret, Now: func() time.Time { return time.UnixMilli(fc.ValidateAt) }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOfficialFormat1StatelessFixture(t *testing.T) {
	fc := loadVectors(t).Format1
	c := fixtureCap(t, fc)
	if fc.Challenge.Count != 2 || fc.Challenge.Format != 1 {
		t.Fatalf("fixture = %+v", fc.Challenge)
	}
	// Our derivation of salts/targets must match what solved the fixture.
	solutions, _ := SolveChallenge(&fc.Challenge)
	var got, want []int64
	_ = json.Unmarshal(solutions, &got)
	_ = json.Unmarshal(fc.RedeemBody.Solutions, &want)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("solutions %v != fixture %v", got, want)
	}
	token, err := c.Redeem(context.Background(), fc.RedeemBody, RedeemOptions{Scope: fc.Scope})
	if err != nil {
		t.Fatalf("official format-1 fixture rejected: %v", err)
	}
	if token.Scope != "login" {
		t.Fatalf("token = %+v", token)
	}
}

func TestOfficialFormat2PoWFixture(t *testing.T) {
	fc := loadVectors(t).Format2
	c := fixtureCap(t, fc)
	solutions, _ := SolveChallenge(&fc.Challenge)
	var got, want []map[string]int64
	_ = json.Unmarshal(solutions, &got)
	_ = json.Unmarshal(fc.RedeemBody.Solutions, &want)
	if len(got) != len(want) || got[0]["nonce"] != want[0]["nonce"] {
		t.Fatalf("solutions %s != fixture %s", solutions, fc.RedeemBody.Solutions)
	}
	if _, err := c.Redeem(context.Background(), fc.RedeemBody, RedeemOptions{Scope: fc.Scope}); err != nil {
		t.Fatalf("official format-2 pow fixture rejected: %v", err)
	}
}

func TestOfficialInstrumentationFixtures(t *testing.T) {
	v := loadVectors(t)
	meta := v.Instr.Meta
	if err := VerifyInstrumentationResult(&meta, v.Instr.GoodResult); err != nil {
		t.Fatalf("good result rejected: %v", err)
	}
	var good InstrumentationResult
	_ = json.Unmarshal(v.Instr.GoodResult, &good)
	good.State[meta.Vars[0]] = json.RawMessage(`1`)
	bad, _ := json.Marshal(good)
	if err := VerifyInstrumentationResult(&meta, bad); ReasonOf(err) != ReasonInstrFailedChallenge {
		t.Fatalf("bad result err = %v", err)
	}
	// The official blob is deflate-raw + base64 and decodes to JavaScript.
	script := inflateBlob(t, v.Instr.Blob)
	if !strings.Contains(script, "cap:instr") || !strings.Contains(script, meta.Vars[0]) {
		t.Fatalf("unexpected official script: %.80s", script)
	}

	f1 := v.Format1Instr
	c := fixtureCap(t, f1.fixtureCase)
	if _, err := c.Redeem(context.Background(), f1.RedeemBody, RedeemOptions{Scope: f1.Scope}); err != nil {
		t.Fatalf("format-1 instr fixture rejected: %v", err)
	}
	missing := f1.RedeemBody
	missing.Instr = nil
	c = fixtureCap(t, f1.fixtureCase)
	if err := redeemErr(c, missing, f1.Scope); ReasonOf(err) != f1.MissingInstrReason {
		t.Fatalf("missing instr err = %v want %s", err, f1.MissingInstrReason)
	}

	f2 := v.Format2Instr
	c = fixtureCap(t, f2.fixtureCase)
	if _, err := c.Redeem(context.Background(), f2.RedeemBody, RedeemOptions{Scope: f2.Scope}); err != nil {
		t.Fatalf("format-2 instr fixture rejected: %v", err)
	}
	var sols []json.RawMessage
	_ = json.Unmarshal(f2.RedeemBody.Solutions, &sols)
	for _, tc := range []struct{ entry, want string }{{`{"blocked":true}`, f2.BlockedReason}, {`{"timeout":true}`, f2.TimeoutReason}, {`{}`, ReasonInstrMissing}} {
		body, _ := json.Marshal([]json.RawMessage{sols[0], json.RawMessage(tc.entry)})
		c = fixtureCap(t, f2.fixtureCase)
		err := redeemErr(c, RedeemRequest{Token: f2.RedeemBody.Token, Solutions: body}, f2.Scope)
		var pe *Error
		if ReasonOf(err) != tc.want || !errors.As(err, &pe) || !pe.Instr {
			t.Fatalf("%s: err = %v want %s", tc.entry, err, tc.want)
		}
	}
}

func redeemErr(c *Cap, req RedeemRequest, scope string) error {
	_, err := c.Redeem(context.Background(), req, RedeemOptions{Scope: scope})
	return err
}

func TestOfficialCapServerStatefulFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/capjs-server-4.0.5-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Challenge Challenge `json:"challenge"`
		Solutions []int64   `json:"solutions"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	// Same token + params must yield the same solutions as @cap.js/server.
	solutions, _ := SolveChallenge(&fixture.Challenge)
	var got []int64
	_ = json.Unmarshal(solutions, &got)
	if len(got) != len(fixture.Solutions) || got[0] != fixture.Solutions[0] || got[1] != fixture.Solutions[1] {
		t.Fatalf("solutions %v != %v", got, fixture.Solutions)
	}
	// Import the challenge as if this replica had issued it.
	c := newTestCap(t, func(o *Options) { o.Secret = nil })
	_ = c.Store().PutChallenge(context.Background(), fixture.Challenge.Token, ChallengeRecord{Count: 2, Size: 32, Difficulty: 1, Expires: time.Now().Add(time.Minute).UnixMilli()})
	body, _ := json.Marshal(fixture.Solutions)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: fixture.Challenge.Token, Solutions: body}, RedeemOptions{}); err != nil {
		t.Fatal(err)
	}
}

// ---- format 1 stateful ----

func TestStatefulFormat1RoundTrip(t *testing.T) {
	c := newTestCap(t, func(o *Options) { o.Secret = nil })
	ch, err := c.Challenge(context.Background(), ChallengeOptions{Scope: "login"})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Format != 1 || len(ch.Token) != 50 || ch.Count != 2 || ch.Size != 32 || ch.Difficulty != 1 {
		t.Fatalf("unexpected challenge %+v", ch)
	}
	wire, _ := json.Marshal(ch)
	if !strings.Contains(string(wire), `"challenge":{"c":2,"s":32,"d":1}`) {
		t.Fatalf("wire = %s", wire)
	}
	token := solveAndRedeem(t, c, ch, "login")
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{Scope: "signup"}); ok {
		t.Fatal("wrong scope accepted")
	}
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{Scope: "login"}); !ok {
		t.Fatal("token rejected")
	}
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{Scope: "login"}); ok {
		t.Fatal("token reused")
	}
	// Challenge is single use too.
	solutions, _ := SolveChallenge(ch)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed challenge error = %v", err)
	}
}

func TestStatefulRejectsWrongSolution(t *testing.T) {
	c := newTestCap(t, func(o *Options) { o.Secret = nil })
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	body, _ := json.Marshal([]int64{1, 2})
	_, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: body}, RedeemOptions{})
	if !errors.Is(err, ErrInvalidSolution) && !errors.Is(err, ErrInvalidSolutions) {
		t.Fatalf("error = %v", err)
	}
	// A failed attempt burns the stored challenge, like @cap.js/server.
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: body}, RedeemOptions{}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("second error = %v", err)
	}
}

func TestStatefulExpiryIsMillisecondPrecise(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	c := newTestCap(t, func(o *Options) {
		o.Secret = nil
		o.Now = func() time.Time { return now }
		o.ChallengeTTL = time.Minute
	})
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	solutions, _ := SolveChallenge(ch)
	now = now.Add(time.Minute)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{}); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expired challenge error = %v", err)
	}
}

// ---- format 1 stateless ----

func TestStatelessFormat1RoundTripAndReplay(t *testing.T) {
	c := newTestCap(t, func(o *Options) { o.Stateless = true })
	ch, err := c.Challenge(context.Background(), ChallengeOptions{Scope: "signup", Extra: map[string]any{"ip": "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ch.Token, ".") != 2 {
		t.Fatalf("expected JWT token, got %q", ch.Token)
	}
	solutions, _ := SolveChallenge(ch)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: "login"}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("scope error = %v", err)
	}
	token, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: "signup"})
	if err != nil {
		t.Fatal(err)
	}
	if token.Scope != "signup" || token.IssuedAt == 0 {
		t.Fatalf("token = %+v", token)
	}
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: "signup"}); !errors.Is(err, ErrAlreadyRedeemed) {
		t.Fatalf("replay error = %v", err)
	}
	// Tampered signature.
	tampered := ch.Token[:len(ch.Token)-1] + "A"
	if tampered == ch.Token {
		tampered = ch.Token[:len(ch.Token)-1] + "B"
	}
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: tampered, Solutions: solutions}, RedeemOptions{}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestStatelessWrongSolutionDoesNotBurnNonce(t *testing.T) {
	c := newTestCap(t, func(o *Options) { o.Stateless = true })
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	bad, _ := json.Marshal([]int64{0, 0})
	_, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: bad}, RedeemOptions{})
	if !errors.Is(err, ErrInvalidSolution) {
		t.Fatalf("error = %v", err)
	}
	solveAndRedeem(t, c, ch, "")
}

// ---- format 2 ----

func TestFormat2AllProtocols(t *testing.T) {
	c := newTestCap(t, func(o *Options) {
		o.Format = 2
		o.RSWKeypair = loadTestKeypair(t)
		o.Protocols = []Protocol{ProtocolSHA256PoW, ProtocolRSW}
	})
	ch, err := c.Challenge(context.Background(), ChallengeOptions{Scope: "login"})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Format != 2 || len(ch.Challenges) != 3 {
		t.Fatalf("challenge = %+v", ch)
	}
	wire, _ := json.Marshal(ch)
	var decoded Challenge
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if rsw, ok := decoded.Challenges[2].Payload.(RSWPayload); !ok || len(rsw.N) != 512 || rsw.T != 2000 {
		t.Fatalf("rsw payload = %#v", decoded.Challenges[2].Payload)
	}
	token := solveAndRedeem(t, c, &decoded, "login")
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{Scope: "login"}); !ok {
		t.Fatal("token rejected")
	}
}

func TestFormat2RejectsWrongAndReplayed(t *testing.T) {
	c := newTestCap(t, func(o *Options) {
		o.Format = 2
		o.RSWKeypair = loadTestKeypair(t)
	})
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{Scope: "login"})
	wrong, _ := json.Marshal([]map[string]any{{"y": "1"}})
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: wrong}, RedeemOptions{Scope: "login"}); !errors.Is(err, ErrInvalidSolution) {
		t.Fatalf("wrong error = %v", err)
	}
	short, _ := json.Marshal([]map[string]any{})
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: short}, RedeemOptions{Scope: "login"}); !errors.Is(err, ErrInvalidSolutions) {
		t.Fatalf("short error = %v", err)
	}
	solutions, _ := SolveChallenge(ch)
	// Uppercase / 0x-prefixed hex must still be accepted.
	var sols []map[string]string
	_ = json.Unmarshal(solutions, &sols)
	sols[0]["y"] = "0x" + strings.ToUpper(sols[0]["y"])
	solutions, _ = json.Marshal(sols)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: "login"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{Scope: "login"}); !errors.Is(err, ErrAlreadyRedeemed) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestFormat2ExpiryBoundary(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	c := newTestCap(t, func(o *Options) {
		o.Format = 2
		o.RSWKeypair = loadTestKeypair(t)
		o.ChallengeTTL = time.Minute
		o.Now = func() time.Time { return now }
	})
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	solutions, _ := SolveChallenge(ch)
	now = now.Add(time.Minute + time.Millisecond)
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions}, RedeemOptions{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("error = %v", err)
	}
}

func TestOfficialCapjsCoreFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/capjs-core-0.1.1-rsw.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source     string        `json:"source"`
		SecretHex  string        `json:"secretHex"`
		Scope      string        `json:"scope"`
		ValidateAt int64         `json:"validateAt"`
		Challenge  Challenge     `json:"challenge"`
		RedeemBody RedeemRequest `json:"redeemBody"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	secret, _ := hex.DecodeString(fixture.SecretHex)
	c, err := New(Options{Secret: secret, Now: func() time.Time { return time.UnixMilli(fixture.ValidateAt) }})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.Challenge.Format != 2 || fixture.Challenge.Token != fixture.RedeemBody.Token {
		t.Fatal("fixture shape changed")
	}
	if _, err := c.Redeem(context.Background(), fixture.RedeemBody, RedeemOptions{Scope: "other"}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("scope error = %v", err)
	}
	token, err := c.Redeem(context.Background(), fixture.RedeemBody, RedeemOptions{Scope: fixture.Scope})
	if err != nil {
		t.Fatalf("official fixture rejected: %v", err)
	}
	if token.Scope != "login" || token.IssuedAt != 1700000000000 {
		t.Fatalf("token = %+v", token)
	}
	if _, err := c.Redeem(context.Background(), fixture.RedeemBody, RedeemOptions{Scope: fixture.Scope}); !errors.Is(err, ErrAlreadyRedeemed) {
		t.Fatalf("replay error = %v", err)
	}
}

// ---- tokens ----

func TestTokenIsConsumedExactlyOnceConcurrently(t *testing.T) {
	c := newTestCap(t, nil)
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	token := solveAndRedeem(t, c, ch, "")
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{}); ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("token accepted %d times", successes.Load())
	}
}

func TestKeepTokenAndExpiry(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	c := newTestCap(t, func(o *Options) {
		o.Now = func() time.Time { return now }
		o.TokenTTL = time.Minute
	})
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	token := solveAndRedeem(t, c, ch, "")
	for i := 0; i < 3; i++ {
		if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{Keep: true}); !ok {
			t.Fatal("kept token rejected")
		}
	}
	now = now.Add(time.Minute)
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{}); ok {
		t.Fatal("expired token accepted")
	}
	if ok, _ := c.Validate(context.Background(), "garbage", ValidateOptions{}); ok {
		t.Fatal("garbage accepted")
	}
}

func TestCustomSignToken(t *testing.T) {
	issued := map[string]TokenClaims{}
	c := newTestCap(t, func(o *Options) {
		o.SignToken = func(_ context.Context, claims TokenClaims) (string, error) {
			issued["custom"] = claims
			return "custom", nil
		}
		o.VerifyToken = func(_ context.Context, token, scope string) (bool, error) {
			claims, ok := issued[token]
			return ok && claims.Scope == scope, nil
		}
	})
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{Scope: "x"})
	token := solveAndRedeem(t, c, ch, "x")
	if token.Token != "custom" {
		t.Fatalf("token = %+v", token)
	}
	if ok, _ := c.Validate(context.Background(), "custom", ValidateOptions{Scope: "x"}); !ok {
		t.Fatal("custom token rejected")
	}
}

func TestResetInvalidatesEverything(t *testing.T) {
	c := newTestCap(t, nil)
	ch, _ := c.Challenge(context.Background(), ChallengeOptions{})
	token := solveAndRedeem(t, c, ch, "")
	if err := c.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Validate(context.Background(), token.Token, ValidateOptions{}); ok {
		t.Fatal("token survived reset")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	cases := []Options{
		{Secret: []byte("short")},
		{Format: 2},
		{Stateless: true},
		{Format: 3, Secret: testSecret},
		{ChallengeDifficulty: 17},
		{Protocols: []Protocol{"bogus"}, Secret: testSecret},
		{Secret: testSecret, SignToken: func(context.Context, TokenClaims) (string, error) { return "", nil }},
	}
	for i, opts := range cases {
		if _, err := New(opts); !errors.Is(err, ErrConfig) {
			t.Fatalf("case %d: err = %v", i, err)
		}
	}
	c := newTestCap(t, func(o *Options) { o.Format = 2 })
	if _, err := c.Challenge(context.Background(), ChallengeOptions{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("rsw without keypair err = %v", err)
	}
}

func TestRedeemBodyValidation(t *testing.T) {
	c := newTestCap(t, nil)
	cases := []struct {
		req  RedeemRequest
		want error
	}{
		{RedeemRequest{}, ErrMissingToken},
		{RedeemRequest{Token: "abc"}, ErrMissingSolutions},
		{RedeemRequest{Token: strings.Repeat("a", 50), Solutions: json.RawMessage(`"x"`)}, ErrInvalidSolutions},
		{RedeemRequest{Token: strings.Repeat("a", 50), Solutions: json.RawMessage(`[1]`)}, ErrChallengeNotFound},
		{RedeemRequest{Token: "a.b.c", Solutions: json.RawMessage(`[1]`)}, ErrInvalidToken},
	}
	for i, tc := range cases {
		if _, err := c.Redeem(context.Background(), tc.req, RedeemOptions{}); !errors.Is(err, tc.want) {
			t.Fatalf("case %d: err = %v want %v", i, err, tc.want)
		}
	}
}

func TestGCMTamperingRejected(t *testing.T) {
	blob, err := encryptGCM(testSecret, "cap:fmt2-v1", []byte(`{"expected":[]}`), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := decryptGCM(testSecret, "cap:fmt2-v1", blob); !ok || string(got) != `{"expected":[]}` {
		t.Fatal("round trip failed")
	}
	raw, _ := decodeBase64URL(blob)
	raw[len(raw)-1] ^= 1
	if _, ok := decryptGCM(testSecret, "cap:fmt2-v1", strings.TrimRight(string(mustB64(raw)), "=")); ok {
		t.Fatal("tampered blob accepted")
	}
	if _, ok := decryptGCM(testSecret, "cap:enc-v1", blob); ok {
		t.Fatal("wrong info accepted")
	}
}

func mustB64(raw []byte) []byte {
	return []byte(strings.NewReplacer("+", "-", "/", "_").Replace(base64Std(raw)))
}

func base64Std(raw []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(raw); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], raw[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])
		out.WriteByte(table[v>>18&63])
		out.WriteByte(table[v>>12&63])
		if n > 1 {
			out.WriteByte(table[v>>6&63])
		}
		if n > 2 {
			out.WriteByte(table[v&63])
		}
	}
	return out.String()
}
