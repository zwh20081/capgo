package capgo

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Protocol identifies a format-2 puzzle type.
type Protocol string

const (
	// ProtocolSHA256PoW is the classic hashcash puzzle: find nonce such that
	// sha256(salt + nonce) starts with target.
	ProtocolSHA256PoW Protocol = "sha256-pow"
	// ProtocolRSW is the repeated-squaring time-lock puzzle: compute
	// x^(2^t) mod N. Sequential by nature, so it cannot be parallelised.
	ProtocolRSW Protocol = "rsw"
	// ProtocolInstrumentation runs a randomized environment probe in a
	// sandboxed iframe and reports the resulting program state.
	ProtocolInstrumentation Protocol = "instrumentation"
)

// Defaults shared with @cap.js/server and capjs-core.
const (
	DefaultChallengeCount      = 50
	DefaultChallengeSize       = 32
	DefaultChallengeDifficulty = 4
	DefaultChallengeTTL        = 10 * time.Minute
	DefaultTokenTTL            = 20 * time.Minute
	DefaultRSWIterations       = 75_000

	MaxChallengeCount      = 1000
	MaxChallengeSize       = 256
	MaxChallengeDifficulty = 16

	challengeTokenBytes = 25 // stateful format-1 token: 50 hex chars
	tokenIDBytes        = 8
	tokenVerifierBytes  = 15
	cleanupInterval     = 5 * time.Minute
)

// ErrConfig is returned for invalid configuration or unmet requirements
// (for example a format-2 challenge without a secret).
var ErrConfig = errors.New("capgo: configuration error")

// Options configures a Cap instance. The zero value is usable for stateful
// format-1 challenges with an in-memory store; set Secret to enable signed
// challenges and format 2.
type Options struct {
	// Secret is the HMAC master key for signed (stateless) challenges and
	// format 2. Must be at least 16 bytes; use 32 random bytes. Keep it
	// identical across replicas.
	Secret []byte
	// Store holds challenges, nonces and verification tokens. Defaults to a
	// new MemoryStore.
	Store Store
	// Random defaults to crypto/rand.Reader.
	Random io.Reader
	// Now defaults to time.Now; override in tests.
	Now func() time.Time

	// Format selects the default wire format: 1 (default) or 2.
	Format int
	// Stateless makes format-1 challenges self-contained signed tokens
	// (capjs-core style) instead of stored records (@cap.js/server style).
	// Requires Secret.
	Stateless bool
	// Protocols lists the format-2 puzzles to include, in order. Defaults to
	// [ProtocolRSW]. Instrumentation is added automatically when
	// Instrumentation is set and the list does not already contain it.
	Protocols []Protocol

	// ChallengeCount, ChallengeSize and ChallengeDifficulty tune sha256-pow.
	ChallengeCount      int
	ChallengeSize       int
	ChallengeDifficulty int
	// ChallengeTTL bounds how long a challenge may be solved.
	ChallengeTTL time.Duration
	// TokenTTL bounds how long an issued verification token stays valid.
	TokenTTL time.Duration

	// RSWKeypair is required for ProtocolRSW. Persist it; generation is slow.
	RSWKeypair *RSWKeypair
	// RSWIterations is the squaring count t (default 75000, ~0.3-0.8 s in a
	// browser).
	RSWIterations int

	// Instrumentation enables the browser-environment probe. For format 1
	// the blob rides in the "instrumentation" field; for format 2 it becomes
	// a challenge entry.
	Instrumentation *InstrumentationOptions
	// InstrumentationGenerator replaces the built-in generator when instrumentation
	// is enabled. A nil value uses the Go implementation.
	InstrumentationGenerator InstrumentationGenerator

	// SignToken, when set, replaces the random stored verification token
	// with a caller-defined one (capjs-core's signToken). Validate then
	// delegates to VerifyToken, which must be set as well.
	SignToken func(ctx context.Context, claims TokenClaims) (string, error)
	// VerifyToken validates a token produced by SignToken. It must enforce
	// expiry, scope and single use itself.
	VerifyToken func(ctx context.Context, token, scope string) (bool, error)
}

// TokenClaims describes a verification token being issued.
type TokenClaims struct {
	Scope    string
	Expires  int64 // Unix milliseconds
	IssuedAt int64 // Unix milliseconds the challenge was created
}

// Cap generates, redeems and validates Cap challenges. It is safe for
// concurrent use.
type Cap struct {
	opts Options

	mu          sync.Mutex
	minters     map[int]*RSWMinter
	lastCleanup time.Time
}

// New validates opts and returns a ready Cap.
func New(opts Options) (*Cap, error) {
	if len(opts.Secret) > 0 && len(opts.Secret) < 16 {
		return nil, fmt.Errorf("%w: secret must be at least 16 bytes", ErrConfig)
	}
	if opts.Store == nil {
		opts.Store = NewMemoryStore()
	}
	if opts.Random == nil {
		opts.Random = rand.Reader
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Format == 0 {
		opts.Format = 1
	}
	if opts.Format != 1 && opts.Format != 2 {
		return nil, fmt.Errorf("%w: format must be 1 or 2", ErrConfig)
	}
	if opts.ChallengeCount == 0 {
		opts.ChallengeCount = DefaultChallengeCount
	}
	if opts.ChallengeSize == 0 {
		opts.ChallengeSize = DefaultChallengeSize
	}
	if opts.ChallengeDifficulty == 0 {
		opts.ChallengeDifficulty = DefaultChallengeDifficulty
	}
	if err := validatePoWParams(opts.ChallengeCount, opts.ChallengeSize, opts.ChallengeDifficulty); err != nil {
		return nil, err
	}
	if opts.ChallengeTTL == 0 {
		opts.ChallengeTTL = DefaultChallengeTTL
	}
	if opts.TokenTTL == 0 {
		opts.TokenTTL = DefaultTokenTTL
	}
	if opts.ChallengeTTL < 0 || opts.TokenTTL < 0 {
		return nil, fmt.Errorf("%w: TTLs must be positive", ErrConfig)
	}
	if opts.RSWIterations == 0 {
		opts.RSWIterations = DefaultRSWIterations
	}
	if opts.RSWIterations < 1 {
		return nil, fmt.Errorf("%w: RSWIterations must be positive", ErrConfig)
	}
	if opts.RSWKeypair != nil {
		if err := opts.RSWKeypair.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConfig, err)
		}
	}
	if len(opts.Protocols) == 0 {
		opts.Protocols = []Protocol{ProtocolRSW}
	}
	for _, p := range opts.Protocols {
		switch p {
		case ProtocolSHA256PoW, ProtocolRSW, ProtocolInstrumentation:
		default:
			return nil, fmt.Errorf("%w: unknown protocol %q", ErrConfig, p)
		}
	}
	if (opts.SignToken == nil) != (opts.VerifyToken == nil) {
		return nil, fmt.Errorf("%w: SignToken and VerifyToken must be set together", ErrConfig)
	}
	if (opts.Stateless || opts.Format == 2) && len(opts.Secret) == 0 {
		return nil, fmt.Errorf("%w: Secret is required for stateless or format-2 challenges", ErrConfig)
	}
	return &Cap{opts: opts, minters: map[int]*RSWMinter{}}, nil
}

func validatePoWParams(count, size, difficulty int) error {
	if count < 1 || count > MaxChallengeCount || size < 1 || size > MaxChallengeSize || difficulty < 1 || difficulty > MaxChallengeDifficulty {
		return fmt.Errorf("%w: c in [1,%d], s in [1,%d], d in [1,%d]", ErrConfig, MaxChallengeCount, MaxChallengeSize, MaxChallengeDifficulty)
	}
	return nil
}

// Options returns a copy of the effective configuration.
func (c *Cap) Options() Options { return c.opts }

// Store exposes the configured store.
func (c *Cap) Store() Store { return c.opts.Store }

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

// ChallengeOptions customises a single challenge. Zero values fall back to
// the Cap-level Options.
type ChallengeOptions struct {
	// Scope binds the challenge (and the resulting token) to an action such
	// as "login". Redeem and Validate with the same scope to enforce it.
	Scope string
	// Extra is embedded in signed tokens as claim "x" (not available for
	// stateful challenges).
	Extra map[string]any

	Format    int
	Stateless *bool
	Protocols []Protocol

	ChallengeCount      int
	ChallengeSize       int
	ChallengeDifficulty int
	ChallengeTTL        time.Duration

	// Instrumentation overrides Options.Instrumentation for this challenge.
	// Set DisableInstrumentation to force it off.
	Instrumentation        *InstrumentationOptions
	DisableInstrumentation bool
	// InstrumentationGenerator overrides the instance's generator for this call.
	InstrumentationGenerator InstrumentationGenerator
}

// Challenge is a generated challenge. Marshal it to JSON and return it from
// your /challenge endpoint; the shape depends on Format.
type Challenge struct {
	Format  int
	Token   string
	Expires int64 // Unix milliseconds
	Scope   string

	// Format 1
	Count           int
	Size            int
	Difficulty      int
	Instrumentation string // base64 deflate-raw script, if enabled

	// Format 2
	Challenges []ChallengeEntry
}

// ChallengeEntry is one format-2 puzzle.
type ChallengeEntry struct {
	Protocol Protocol `json:"protocol"`
	Payload  any      `json:"payload"`
}

// PoWPayload is the payload of a sha256-pow entry.
type PoWPayload struct {
	Salt   string `json:"salt"`
	Target string `json:"target"`
}

// RSWPayload is the payload of an rsw entry (all hex).
type RSWPayload struct {
	N string `json:"N"`
	X string `json:"x"`
	T int    `json:"t"`
}

// InstrumentationPayload is the payload of an instrumentation entry.
type InstrumentationPayload struct {
	Blob string `json:"blob"`
}

type format1JSON struct {
	Challenge struct {
		C int `json:"c"`
		S int `json:"s"`
		D int `json:"d"`
	} `json:"challenge"`
	Token           string `json:"token"`
	Expires         int64  `json:"expires"`
	Instrumentation string `json:"instrumentation,omitempty"`
}

type format2JSON struct {
	Token      string           `json:"token"`
	Format     int              `json:"format"`
	Challenges []ChallengeEntry `json:"challenges"`
	Expires    int64            `json:"expires"`
}

// MarshalJSON emits the exact wire shape the widget expects.
func (ch Challenge) MarshalJSON() ([]byte, error) {
	if ch.Format == 2 {
		entries := ch.Challenges
		if entries == nil {
			entries = []ChallengeEntry{}
		}
		return json.Marshal(format2JSON{Token: ch.Token, Format: 2, Challenges: entries, Expires: ch.Expires})
	}
	var out format1JSON
	out.Challenge.C, out.Challenge.S, out.Challenge.D = ch.Count, ch.Size, ch.Difficulty
	out.Token, out.Expires, out.Instrumentation = ch.Token, ch.Expires, ch.Instrumentation
	return json.Marshal(out)
}

// UnmarshalJSON accepts either wire shape (useful for Go clients and tests).
func (ch *Challenge) UnmarshalJSON(data []byte) error {
	var probe struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Format == 2 {
		var raw struct {
			Token      string `json:"token"`
			Expires    int64  `json:"expires"`
			Challenges []struct {
				Protocol Protocol        `json:"protocol"`
				Payload  json.RawMessage `json:"payload"`
			} `json:"challenges"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		*ch = Challenge{Format: 2, Token: raw.Token, Expires: raw.Expires}
		for _, entry := range raw.Challenges {
			var payload any
			switch entry.Protocol {
			case ProtocolSHA256PoW:
				var p PoWPayload
				if err := json.Unmarshal(entry.Payload, &p); err != nil {
					return err
				}
				payload = p
			case ProtocolRSW:
				var p RSWPayload
				if err := json.Unmarshal(entry.Payload, &p); err != nil {
					return err
				}
				payload = p
			case ProtocolInstrumentation:
				var p InstrumentationPayload
				if err := json.Unmarshal(entry.Payload, &p); err != nil {
					return err
				}
				payload = p
			default:
				payload = entry.Payload
			}
			ch.Challenges = append(ch.Challenges, ChallengeEntry{Protocol: entry.Protocol, Payload: payload})
		}
		return nil
	}
	var raw format1JSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*ch = Challenge{Format: 1, Token: raw.Token, Expires: raw.Expires, Count: raw.Challenge.C, Size: raw.Challenge.S, Difficulty: raw.Challenge.D, Instrumentation: raw.Instrumentation}
	return nil
}

// Format1Pairs returns the (salt, target) pairs a client must solve for a
// format-1 challenge, in order.
func (ch Challenge) Format1Pairs() [][2]string {
	pairs := make([][2]string, ch.Count)
	for i := range pairs {
		salt, target := format1Pair(ch.Token, i+1, ch.Size, ch.Difficulty)
		pairs[i] = [2]string{salt, target}
	}
	return pairs
}

// signed token claims (format 1 stateless and format 2)
type tokenClaims struct {
	F   int            `json:"f,omitempty"`
	N   string         `json:"n"`
	C   int            `json:"c,omitempty"`
	S   int            `json:"s,omitempty"`
	D   int            `json:"d,omitempty"`
	Exp int64          `json:"exp"`
	Iat int64          `json:"iat"`
	Sk  string         `json:"sk,omitempty"`
	X   map[string]any `json:"x,omitempty"`
	Ei  string         `json:"ei,omitempty"` // format-1 encrypted instrumentation meta
	Ev  string         `json:"ev,omitempty"` // format-2 encrypted expected solutions
}

type expectedEntry struct {
	Protocol  Protocol             `json:"protocol"`
	Salt      string               `json:"salt,omitempty"`
	Target    string               `json:"target,omitempty"`
	Y         string               `json:"y,omitempty"`
	InstrMeta *InstrumentationMeta `json:"instrMeta,omitempty"`
}

type expectedEnvelope struct {
	Expected []expectedEntry `json:"expected"`
}

func (c *Cap) now() time.Time { return c.opts.Now() }

func (c *Cap) lazyCleanup(ctx context.Context) {
	now := c.now()
	c.mu.Lock()
	due := c.lastCleanup.IsZero() || now.Sub(c.lastCleanup) >= cleanupInterval
	if due {
		c.lastCleanup = now
	}
	c.mu.Unlock()
	if due {
		_ = c.opts.Store.Cleanup(ctx, now.UnixMilli())
	}
}

// Cleanup removes expired state from the store immediately.
func (c *Cap) Cleanup(ctx context.Context) error {
	return c.opts.Store.Cleanup(ctx, c.now().UnixMilli())
}

// Reset drops all outstanding challenges, nonces and tokens (for example
// after rotating Secret or the RSW keypair).
func (c *Cap) Reset(ctx context.Context) error {
	c.mu.Lock()
	c.minters = map[int]*RSWMinter{}
	c.mu.Unlock()
	return c.opts.Store.Reset(ctx)
}

func (c *Cap) minter() (*RSWMinter, error) {
	if c.opts.RSWKeypair == nil {
		return nil, fmt.Errorf("%w: ProtocolRSW requires RSWKeypair", ErrConfig)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.minters[c.opts.RSWIterations]; ok {
		return m, nil
	}
	m, err := NewRSWMinter(c.opts.RSWKeypair, c.opts.RSWIterations, c.opts.Random, nil)
	if err != nil {
		return nil, err
	}
	c.minters[c.opts.RSWIterations] = m
	return m, nil
}

func (c *Cap) instrumentationOptions(o ChallengeOptions) *InstrumentationOptions {
	if o.DisableInstrumentation {
		return nil
	}
	if o.Instrumentation != nil {
		return o.Instrumentation
	}
	return c.opts.Instrumentation
}

// Challenge creates a new challenge.
func (c *Cap) Challenge(ctx context.Context, o ChallengeOptions) (*Challenge, error) {
	c.lazyCleanup(ctx)
	format := c.opts.Format
	if o.Format != 0 {
		format = o.Format
	}
	switch format {
	case 1:
		stateless := c.opts.Stateless
		if o.Stateless != nil {
			stateless = *o.Stateless
		}
		if stateless {
			return c.challengeSigned(ctx, o)
		}
		return c.challengeStored(ctx, o)
	case 2:
		return c.challengeV2(ctx, o)
	default:
		return nil, fmt.Errorf("%w: format must be 1 or 2", ErrConfig)
	}
}

func (c *Cap) powParams(o ChallengeOptions) (count, size, difficulty int, err error) {
	count, size, difficulty = c.opts.ChallengeCount, c.opts.ChallengeSize, c.opts.ChallengeDifficulty
	if o.ChallengeCount != 0 {
		count = o.ChallengeCount
	}
	if o.ChallengeSize != 0 {
		size = o.ChallengeSize
	}
	if o.ChallengeDifficulty != 0 {
		difficulty = o.ChallengeDifficulty
	}
	return count, size, difficulty, validatePoWParams(count, size, difficulty)
}

func (c *Cap) challengeTTL(o ChallengeOptions) time.Duration {
	if o.ChallengeTTL > 0 {
		return o.ChallengeTTL
	}
	return c.opts.ChallengeTTL
}

func (c *Cap) generateInstrumentation(ctx context.Context, o ChallengeOptions, ttl time.Duration, now time.Time) (*Instrumentation, error) {
	io := c.instrumentationOptions(o)
	if io == nil {
		return nil, nil
	}
	opts := *io
	if opts.TTL <= 0 {
		opts.TTL = ttl
	}
	return c.runInstrumentationGenerator(ctx, o, opts, now)
}

func (c *Cap) runInstrumentationGenerator(ctx context.Context, o ChallengeOptions, opts InstrumentationOptions, now time.Time) (*Instrumentation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	generator := o.InstrumentationGenerator
	if generator == nil {
		generator = c.opts.InstrumentationGenerator
	}
	var instr *Instrumentation
	var err error
	if generator == nil {
		instr, err = GenerateInstrumentation(c.opts.Random, opts, now)
	} else {
		instr, err = generator(ctx, c.opts.Random, opts, now)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if instr == nil || instr.Blob == "" || instr.Meta.ID == "" || len(instr.Meta.Vars) == 0 || len(instr.Meta.Vars) != len(instr.Meta.ExpectedVals) {
		return nil, fmt.Errorf("%w: instrumentation generator returned invalid output", ErrConfig)
	}
	seen := make(map[string]bool, len(instr.Meta.Vars))
	for _, name := range instr.Meta.Vars {
		if name == "" || seen[name] {
			return nil, fmt.Errorf("%w: instrumentation generator returned invalid variables", ErrConfig)
		}
		seen[name] = true
	}
	if instr.Meta.BlockAutomatedBrowsers != opts.BlockAutomatedBrowsers {
		return nil, fmt.Errorf("%w: instrumentation generator changed browser blocking policy", ErrConfig)
	}
	// Keep stored metadata independent of a generator's reusable result.
	result := *instr
	result.Meta.Vars = append([]string(nil), instr.Meta.Vars...)
	result.Meta.ExpectedVals = append([]int32(nil), instr.Meta.ExpectedVals...)
	if result.Meta.Expires == 0 {
		result.Meta.Expires = now.Add(opts.TTL).UnixMilli()
	}
	return &result, nil
}

func (c *Cap) challengeStored(ctx context.Context, o ChallengeOptions) (*Challenge, error) {
	count, size, difficulty, err := c.powParams(o)
	if err != nil {
		return nil, err
	}
	now := c.now()
	ttl := c.challengeTTL(o)
	expires := now.UnixMilli() + ttl.Milliseconds()
	token, err := randomHex(c.opts.Random, challengeTokenBytes)
	if err != nil {
		return nil, err
	}
	record := ChallengeRecord{Count: count, Size: size, Difficulty: difficulty, Scope: o.Scope, Expires: expires}
	instr, err := c.generateInstrumentation(ctx, o, ttl, now)
	if err != nil {
		return nil, err
	}
	if instr != nil {
		meta := instr.Meta
		record.Instr = &meta
	}
	if err := c.opts.Store.PutChallenge(ctx, token, record); err != nil {
		return nil, errors.Join(ErrStore, err)
	}
	ch := &Challenge{Format: 1, Token: token, Expires: expires, Scope: o.Scope, Count: count, Size: size, Difficulty: difficulty}
	if instr != nil {
		ch.Instrumentation = instr.Blob
	}
	return ch, nil
}

func (c *Cap) challengeSigned(ctx context.Context, o ChallengeOptions) (*Challenge, error) {
	if len(c.opts.Secret) == 0 {
		return nil, fmt.Errorf("%w: Secret is required for stateless challenges", ErrConfig)
	}
	count, size, difficulty, err := c.powParams(o)
	if err != nil {
		return nil, err
	}
	now := c.now()
	ttl := c.challengeTTL(o)
	nowMs := now.UnixMilli()
	expires := nowMs + ttl.Milliseconds()
	nonce, err := randomHex(c.opts.Random, challengeTokenBytes)
	if err != nil {
		return nil, err
	}
	claims := tokenClaims{N: nonce, C: count, S: size, D: difficulty, Exp: expires, Iat: nowMs, Sk: o.Scope, X: o.Extra}
	instr, err := c.generateInstrumentation(ctx, o, ttl, now)
	if err != nil {
		return nil, err
	}
	if instr != nil {
		meta := instr.Meta
		meta.Expires = expires
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}
		if claims.Ei, err = encryptGCM(c.opts.Secret, "cap:enc-v1", metaJSON, c.opts.Random); err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	ch := &Challenge{Format: 1, Token: jwtSign(payload, c.opts.Secret), Expires: expires, Scope: o.Scope, Count: count, Size: size, Difficulty: difficulty}
	if instr != nil {
		ch.Instrumentation = instr.Blob
	}
	return ch, nil
}

func (c *Cap) challengeV2(ctx context.Context, o ChallengeOptions) (*Challenge, error) {
	if len(c.opts.Secret) == 0 {
		return nil, fmt.Errorf("%w: Secret is required for format-2 challenges", ErrConfig)
	}
	protocols := c.opts.Protocols
	if len(o.Protocols) > 0 {
		protocols = o.Protocols
	}
	if c.instrumentationOptions(o) != nil && !containsProtocol(protocols, ProtocolInstrumentation) {
		protocols = append(append([]Protocol{}, protocols...), ProtocolInstrumentation)
	}
	now := c.now()
	ttl := c.challengeTTL(o)
	nowMs := now.UnixMilli()
	expires := nowMs + ttl.Milliseconds()

	var entries []ChallengeEntry
	var expected []expectedEntry
	for _, proto := range protocols {
		switch proto {
		case ProtocolSHA256PoW:
			count, size, difficulty, err := c.powParams(o)
			if err != nil {
				return nil, err
			}
			target := strings.Repeat("0", difficulty)
			for i := 0; i < count; i++ {
				salt, err := randomHex(c.opts.Random, size)
				if err != nil {
					return nil, err
				}
				entries = append(entries, ChallengeEntry{Protocol: ProtocolSHA256PoW, Payload: PoWPayload{Salt: salt, Target: target}})
				expected = append(expected, expectedEntry{Protocol: ProtocolSHA256PoW, Salt: salt, Target: target})
			}
		case ProtocolRSW:
			minter, err := c.minter()
			if err != nil {
				return nil, err
			}
			minted, err := minter.Mint()
			if err != nil {
				return nil, err
			}
			entries = append(entries, ChallengeEntry{Protocol: ProtocolRSW, Payload: RSWPayload{
				N: paddedHex(minted.N, minter.modulusBytes), X: paddedHex(minted.X, minter.modulusBytes), T: minted.Iterations,
			}})
			expected = append(expected, expectedEntry{Protocol: ProtocolRSW, Y: paddedHex(minted.ExpectedY, minter.modulusBytes)})
		case ProtocolInstrumentation:
			io := c.instrumentationOptions(o)
			if io == nil {
				io = &InstrumentationOptions{}
			}
			opts := *io
			if opts.TTL <= 0 {
				opts.TTL = ttl
			}
			instr, err := c.runInstrumentationGenerator(ctx, o, opts, now)
			if err != nil {
				return nil, err
			}
			meta := instr.Meta
			meta.Expires = expires
			entries = append(entries, ChallengeEntry{Protocol: ProtocolInstrumentation, Payload: InstrumentationPayload{Blob: instr.Blob}})
			expected = append(expected, expectedEntry{Protocol: ProtocolInstrumentation, InstrMeta: &meta})
		default:
			return nil, fmt.Errorf("%w: unknown protocol %q", ErrConfig, proto)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: no protocols configured", ErrConfig)
	}
	state, err := json.Marshal(expectedEnvelope{Expected: expected})
	if err != nil {
		return nil, err
	}
	ev, err := encryptGCM(c.opts.Secret, "cap:fmt2-v1", state, c.opts.Random)
	if err != nil {
		return nil, err
	}
	nonce, err := randomHex(c.opts.Random, 16)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(tokenClaims{F: 2, N: nonce, Exp: expires, Iat: nowMs, Ev: ev, Sk: o.Scope, X: o.Extra})
	if err != nil {
		return nil, err
	}
	return &Challenge{Format: 2, Token: jwtSign(payload, c.opts.Secret), Expires: expires, Scope: o.Scope, Challenges: entries}, nil
}

func containsProtocol(list []Protocol, p Protocol) bool {
	for _, item := range list {
		if item == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Redemption
// ---------------------------------------------------------------------------

// RedeemRequest is the body the widget POSTs to /redeem.
type RedeemRequest struct {
	Token     string          `json:"token"`
	Solutions json.RawMessage `json:"solutions"`
	// Format-1 instrumentation fields.
	Instr        json.RawMessage `json:"instr,omitempty"`
	InstrBlocked bool            `json:"instr_blocked,omitempty"`
	InstrTimeout bool            `json:"instr_timeout,omitempty"`
}

// Solution is one format-2 solution entry.
type Solution struct {
	Nonce   json.RawMessage `json:"nonce,omitempty"`
	Y       string          `json:"y,omitempty"`
	Instr   json.RawMessage `json:"instr,omitempty"`
	Blocked bool            `json:"blocked,omitempty"`
	Timeout bool            `json:"timeout,omitempty"`
}

// RedeemOptions scopes a redemption.
type RedeemOptions struct {
	// Scope must equal the challenge's scope when non-empty.
	Scope string
	// SkipNonce disables replay protection for signed challenges. Never set
	// this in production; it exists for benchmarking.
	SkipNonce bool
}

// Token is an issued verification token. Return Token and Expires to the
// widget; keep the rest for your own bookkeeping.
type Token struct {
	Token    string `json:"token"`
	Expires  int64  `json:"expires"`
	Scope    string `json:"scope,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
}

// Redeem verifies solutions and issues a verification token. Errors are
// *Error values whose Reason mirrors capjs-core; storage failures wrap
// ErrStore.
func (c *Cap) Redeem(ctx context.Context, req RedeemRequest, o RedeemOptions) (*Token, error) {
	c.lazyCleanup(ctx)
	if req.Token == "" {
		return nil, fail(ReasonMissingToken)
	}
	if len(req.Solutions) == 0 {
		return nil, fail(ReasonMissingSolutions)
	}
	if strings.Contains(req.Token, ".") {
		return c.redeemSigned(ctx, req, o)
	}
	return c.redeemStored(ctx, req, o)
}

func (c *Cap) redeemStored(ctx context.Context, req RedeemRequest, o RedeemOptions) (*Token, error) {
	if len(req.Token) != challengeTokenBytes*2 {
		return nil, fail(ReasonInvalidToken)
	}
	solutions, ok := parseFormat1Solutions(req.Solutions)
	if !ok {
		return nil, fail(ReasonInvalidSolutions)
	}
	nowMs := c.now().UnixMilli()
	record, found, err := c.opts.Store.TakeChallenge(ctx, req.Token, nowMs)
	if err != nil {
		return nil, storeErr(ReasonChallengeNotFound, err)
	}
	if !found {
		return nil, fail(ReasonChallengeNotFound)
	}
	if o.Scope != "" && record.Scope != o.Scope {
		return nil, fail(ReasonScopeMismatch)
	}
	if err := verifyFormat1(req.Token, record.Count, record.Size, record.Difficulty, solutions); err != nil {
		return nil, err
	}
	if record.Instr != nil {
		if err := checkInstrumentation(record.Instr, nowMs, req.Instr, req.InstrBlocked, req.InstrTimeout); err != nil {
			return nil, err
		}
	}
	return c.issueToken(ctx, record.Scope, nowMs, 0)
}

func (c *Cap) redeemSigned(ctx context.Context, req RedeemRequest, o RedeemOptions) (*Token, error) {
	if len(c.opts.Secret) == 0 {
		return nil, fail(ReasonInvalidToken)
	}
	payload, sigHex, ok := jwtVerify(req.Token, c.opts.Secret)
	if !ok {
		return nil, fail(ReasonInvalidToken)
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fail(ReasonInvalidToken)
	}
	if o.Scope != "" && claims.Sk != o.Scope {
		return nil, fail(ReasonScopeMismatch)
	}
	nowMs := c.now().UnixMilli()
	if claims.Exp == 0 || claims.Exp < nowMs {
		return nil, fail(ReasonExpired)
	}

	if claims.F == 2 {
		if err := c.verifyV2(claims, req, nowMs); err != nil {
			return nil, err
		}
	} else {
		if validatePoWParams(claims.C, claims.S, claims.D) != nil {
			return nil, fail(ReasonInvalidToken)
		}
		solutions, ok := parseFormat1Solutions(req.Solutions)
		if !ok {
			return nil, fail(ReasonInvalidSolutions)
		}
		if err := verifyFormat1(req.Token, claims.C, claims.S, claims.D, solutions); err != nil {
			return nil, err
		}
		if claims.Ei != "" {
			metaJSON, ok := decryptGCM(c.opts.Secret, "cap:enc-v1", claims.Ei)
			if !ok {
				return nil, failInstr(ReasonInstrCorrupted)
			}
			var meta InstrumentationMeta
			if json.Unmarshal(metaJSON, &meta) != nil {
				return nil, failInstr(ReasonInstrCorrupted)
			}
			if err := checkInstrumentation(&meta, nowMs, req.Instr, req.InstrBlocked, req.InstrTimeout); err != nil {
				return nil, err
			}
		}
	}

	if !o.SkipNonce {
		claimed, err := c.opts.Store.ClaimNonce(ctx, "nonce:"+sigHex, claims.Exp, nowMs)
		if err != nil {
			return nil, storeErr(ReasonNonceStoreError, err)
		}
		if !claimed {
			return nil, fail(ReasonAlreadyRedeemed)
		}
	}
	return c.issueToken(ctx, claims.Sk, nowMs, claims.Iat)
}

func (c *Cap) verifyV2(claims tokenClaims, req RedeemRequest, nowMs int64) error {
	state, ok := decryptGCM(c.opts.Secret, "cap:fmt2-v1", claims.Ev)
	if !ok {
		return fail(ReasonInvalidToken)
	}
	var envelope expectedEnvelope
	if json.Unmarshal(state, &envelope) != nil || envelope.Expected == nil {
		return fail(ReasonInvalidToken)
	}
	var solutions []json.RawMessage
	if json.Unmarshal(req.Solutions, &solutions) != nil {
		return fail(ReasonMissingSolutions)
	}
	if len(solutions) != len(envelope.Expected) {
		return fail(ReasonInvalidSolutions)
	}
	for i, exp := range envelope.Expected {
		raw := solutions[i]
		if len(raw) == 0 || raw[0] != '{' {
			return fail(ReasonInvalidSolution)
		}
		var sol Solution
		if json.Unmarshal(raw, &sol) != nil {
			return fail(ReasonInvalidSolution)
		}
		switch exp.Protocol {
		case ProtocolSHA256PoW:
			nonce, ok := nonceString(sol.Nonce)
			if !ok || !powMatches(exp.Salt, nonce, exp.Target) {
				return fail(ReasonInvalidSolution)
			}
		case ProtocolRSW:
			if !verifyRSWHex(exp.Y, sol.Y) {
				return fail(ReasonInvalidSolution)
			}
		case ProtocolInstrumentation:
			if err := checkInstrumentation(exp.InstrMeta, nowMs, sol.Instr, sol.Blocked, sol.Timeout); err != nil {
				return err
			}
		default:
			return fail(ReasonInvalidSolution)
		}
	}
	return nil
}

// parseFormat1Solutions accepts an array of JSON numbers (the widget sends
// integers) and renders each exactly as JavaScript would stringify it.
func parseFormat1Solutions(raw json.RawMessage) ([]string, bool) {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return nil, false
	}
	out := make([]string, len(values))
	for i, v := range values {
		s, ok := numberString(v)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// nonceString accepts a JSON number or string (capjs-core format 2).
func nonceString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return s, true
	}
	return numberString(raw)
}

func numberString(raw json.RawMessage) (string, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return "", false
	}
	return jsNumberString(f), true
}

// jsNumberString mimics JavaScript's Number#toString for the values a
// solver can realistically produce (non-negative integers below 2^53).
func jsNumberString(f float64) string {
	if f == float64(int64(f)) && f < 1e21 && f > -1e21 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func verifyFormat1(token string, count, size, difficulty int, solutions []string) error {
	if len(solutions) != count {
		return fail(ReasonInvalidSolutions)
	}
	for i := 0; i < count; i++ {
		salt, target := format1Pair(token, i+1, size, difficulty)
		if !powMatches(salt, solutions[i], target) {
			return fail(ReasonInvalidSolution)
		}
	}
	return nil
}

func powMatches(salt, nonce, target string) bool {
	sum := sha256Sum(salt + nonce)
	return hashHasHexPrefix(sum[:], target)
}

// SolvePoW brute-forces a sha256-pow puzzle. Intended for tests and Go-side
// clients.
func SolvePoW(salt, target string) int64 {
	for nonce := int64(0); ; nonce++ {
		if powMatches(salt, strconv.FormatInt(nonce, 10), target) {
			return nonce
		}
	}
}

// SolveChallenge solves any challenge in Go (format 1 or 2). It is slow by
// design and meant for tests, CLIs and server-to-server flows.
func SolveChallenge(ch *Challenge) (json.RawMessage, error) {
	if ch.Format == 2 {
		solutions := make([]any, 0, len(ch.Challenges))
		for _, entry := range ch.Challenges {
			switch payload := entry.Payload.(type) {
			case PoWPayload:
				solutions = append(solutions, map[string]any{"nonce": SolvePoW(payload.Salt, payload.Target)})
			case RSWPayload:
				n, ok1 := parseHexInt(payload.N)
				x, ok2 := parseHexInt(payload.X)
				if !ok1 || !ok2 {
					return nil, errors.New("capgo: invalid rsw payload")
				}
				solutions = append(solutions, map[string]any{"y": SolveRSW(n, x, payload.T).Text(16)})
			default:
				return nil, fmt.Errorf("capgo: cannot solve protocol %q in Go", entry.Protocol)
			}
		}
		return json.Marshal(solutions)
	}
	nonces := make([]int64, ch.Count)
	for i, pair := range ch.Format1Pairs() {
		nonces[i] = SolvePoW(pair[0], pair[1])
	}
	return json.Marshal(nonces)
}

// ---------------------------------------------------------------------------
// Verification tokens
// ---------------------------------------------------------------------------

func (c *Cap) issueToken(ctx context.Context, scope string, nowMs, iat int64) (*Token, error) {
	expires := nowMs + c.opts.TokenTTL.Milliseconds()
	if c.opts.SignToken != nil {
		signed, err := c.opts.SignToken(ctx, TokenClaims{Scope: scope, Expires: expires, IssuedAt: iat})
		if err != nil {
			return nil, err
		}
		return &Token{Token: signed, Expires: expires, Scope: scope, IssuedAt: iat}, nil
	}
	id, err := randomHex(c.opts.Random, tokenIDBytes)
	if err != nil {
		return nil, err
	}
	verifier, err := randomHex(c.opts.Random, tokenVerifierBytes)
	if err != nil {
		return nil, err
	}
	key := id + ":" + sha256Hex(verifier)
	if err := c.opts.Store.PutToken(ctx, key, TokenRecord{Scope: scope, Expires: expires}); err != nil {
		return nil, errors.Join(ErrStore, err)
	}
	return &Token{Token: id + ":" + verifier, Expires: expires, Scope: scope, IssuedAt: iat}, nil
}

// ValidateOptions controls token validation.
type ValidateOptions struct {
	// Scope must match the scope the token was issued for when non-empty.
	Scope string
	// Keep leaves the token valid after a successful check (multi-use).
	Keep bool
}

// TokenKey converts a verification token into its stored key
// (id + ":" + sha256(verifier)). Returns ok=false for malformed tokens.
func TokenKey(token string) (string, bool) {
	id, verifier, found := strings.Cut(token, ":")
	if !found || id == "" || verifier == "" || strings.Contains(verifier, ":") {
		return "", false
	}
	return id + ":" + sha256Hex(verifier), true
}

// Validate checks a verification token presented by a client and, unless
// Keep is set, consumes it. It returns (true, nil) exactly once per token
// across all replicas sharing the store.
func (c *Cap) Validate(ctx context.Context, token string, o ValidateOptions) (bool, error) {
	c.lazyCleanup(ctx)
	if token == "" {
		return false, nil
	}
	if c.opts.VerifyToken != nil {
		return c.opts.VerifyToken(ctx, token, o.Scope)
	}
	key, ok := TokenKey(token)
	if !ok {
		return false, nil
	}
	_, ok, err := c.opts.Store.ConsumeToken(ctx, key, o.Scope, c.now().UnixMilli(), o.Keep)
	if err != nil {
		return false, errors.Join(ErrStore, err)
	}
	return ok, nil
}
