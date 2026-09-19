package capgo

import (
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// RSWKeypair is the trapdoor for the "rsw" time-lock protocol: N = p*q. The
// public modulus N is sent to clients; p and q must stay secret. Generation is
// slow, so persist the keypair (see MarshalJSON) and reuse it across restarts.
//
// The JSON form {"N","p","q","bits"} (decimal strings) is identical to
// capjs-core's serializeRswKeypair, so keys can be shared with Node servers.
type RSWKeypair struct {
	N    *big.Int
	P    *big.Int
	Q    *big.Int
	Bits int
}

type rswKeypairJSON struct {
	N    string `json:"N"`
	P    string `json:"p"`
	Q    string `json:"q"`
	Bits int    `json:"bits"`
}

// GenerateRSWKeypair creates a fresh keypair. bits must be even and at least
// 1024; 2048 is the recommended (and capjs-core default) size.
func GenerateRSWKeypair(random io.Reader, bits int) (*RSWKeypair, error) {
	if random == nil {
		return nil, errors.New("capgo: random reader is required")
	}
	if bits < 1024 || bits%2 != 0 {
		return nil, errors.New("capgo: rsw bits must be even and >= 1024")
	}
	for {
		key, err := rsa.GenerateKey(random, bits)
		if err != nil {
			return nil, err
		}
		if key.N.BitLen() == bits {
			return &RSWKeypair{N: new(big.Int).Set(key.N), P: new(big.Int).Set(key.Primes[0]), Q: new(big.Int).Set(key.Primes[1]), Bits: bits}, nil
		}
	}
}

// MarshalJSON serializes the keypair in capjs-core's format.
func (k *RSWKeypair) MarshalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(rswKeypairJSON{N: k.N.String(), P: k.P.String(), Q: k.Q.String(), Bits: k.Bits})
}

// UnmarshalJSON parses capjs-core's format and validates the factors.
func (k *RSWKeypair) UnmarshalJSON(data []byte) error {
	var raw rswKeypairJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("capgo: invalid serialized rsw keypair")
	}
	var ok bool
	parsed := RSWKeypair{Bits: raw.Bits}
	if parsed.N, ok = new(big.Int).SetString(raw.N, 10); !ok {
		return errors.New("capgo: invalid rsw modulus")
	}
	if parsed.P, ok = new(big.Int).SetString(raw.P, 10); !ok {
		return errors.New("capgo: invalid rsw factor p")
	}
	if parsed.Q, ok = new(big.Int).SetString(raw.Q, 10); !ok {
		return errors.New("capgo: invalid rsw factor q")
	}
	if parsed.Bits == 0 {
		parsed.Bits = parsed.N.BitLen()
	}
	if err := parsed.Validate(); err != nil {
		return err
	}
	*k = parsed
	return nil
}

// ParseRSWKeypair decodes a keypair previously produced by MarshalJSON (or by
// capjs-core's serializeRswKeypair).
func ParseRSWKeypair(encoded []byte) (*RSWKeypair, error) {
	var k RSWKeypair
	if err := json.Unmarshal(encoded, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// Validate checks that the keypair is well formed (N = p*q, both prime).
func (k *RSWKeypair) Validate() error {
	if k == nil || k.N == nil || k.P == nil || k.Q == nil {
		return errors.New("capgo: rsw keypair is incomplete")
	}
	if k.Bits < 1024 || k.N.BitLen() != k.Bits {
		return errors.New("capgo: rsw modulus size does not match bits")
	}
	if k.P.Cmp(k.Q) == 0 || !k.P.ProbablyPrime(20) || !k.Q.ProbablyPrime(20) {
		return errors.New("capgo: rsw factors must be distinct primes")
	}
	if new(big.Int).Mul(k.P, k.Q).Cmp(k.N) != 0 {
		return errors.New("capgo: rsw factors do not match modulus")
	}
	return nil
}

// RSWMinter produces (x, expectedY) pairs for a fixed keypair and iteration
// count. Building one costs a few modular exponentiations; minting is cheap
// thanks to the CRT trapdoor. It is safe for concurrent use.
type RSWMinter struct {
	N            *big.Int
	Iterations   int
	G            *big.Int
	H            *big.Int
	modulusBytes int
	p, q         *big.Int
	pm1, qm1     *big.Int
	hp, hq       *big.Int
	gp, gq       *big.Int
	qInvP        *big.Int
	random       io.Reader
}

// MintedRSW is a single challenge instance.
type MintedRSW struct {
	N          *big.Int
	X          *big.Int
	ExpectedY  *big.Int
	Iterations int
}

// NewRSWMinter precomputes the trapdoor for iterations squarings. Passing a
// nil generator picks a random one, which is what you want.
func NewRSWMinter(keypair *RSWKeypair, iterations int, random io.Reader, generator *big.Int) (*RSWMinter, error) {
	if err := keypair.Validate(); err != nil {
		return nil, err
	}
	if iterations < 1 || random == nil {
		return nil, errors.New("capgo: invalid rsw minter parameters")
	}
	modulusBytes := (keypair.Bits + 7) / 8
	g := generator
	if g == nil {
		var err error
		if g, err = randomIntRange(random, keypair.N, modulusBytes); err != nil {
			return nil, err
		}
	}
	pm1 := new(big.Int).Sub(keypair.P, big.NewInt(1))
	qm1 := new(big.Int).Sub(keypair.Q, big.NewInt(1))
	exponent := big.NewInt(int64(iterations))
	ep := new(big.Int).Exp(big.NewInt(2), exponent, pm1)
	eq := new(big.Int).Exp(big.NewInt(2), exponent, qm1)
	gp := new(big.Int).Mod(g, keypair.P)
	gq := new(big.Int).Mod(g, keypair.Q)
	hp := new(big.Int).Exp(gp, ep, keypair.P)
	hq := new(big.Int).Exp(gq, eq, keypair.Q)
	qInvP := new(big.Int).ModInverse(new(big.Int).Mod(keypair.Q, keypair.P), keypair.P)
	if qInvP == nil {
		return nil, errors.New("capgo: invalid rsw factors")
	}
	m := &RSWMinter{
		N: new(big.Int).Set(keypair.N), Iterations: iterations, G: g, modulusBytes: modulusBytes,
		p: keypair.P, q: keypair.Q, pm1: pm1, qm1: qm1, hp: hp, hq: hq, gp: gp, gq: gq, qInvP: qInvP, random: random,
	}
	m.H = m.crt(hp, hq)
	return m, nil
}

// Mint draws a fresh 256-bit scalar r and returns x = g^r, y = h^r (mod N),
// so that y == x^(2^t) without anyone but the holder of p, q being able to
// shortcut the t squarings.
func (m *RSWMinter) Mint() (*MintedRSW, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(raw)
	rp := new(big.Int).Mod(r, m.pm1)
	rq := new(big.Int).Mod(r, m.qm1)
	x := m.crt(new(big.Int).Exp(m.gp, rp, m.p), new(big.Int).Exp(m.gq, rq, m.q))
	y := m.crt(new(big.Int).Exp(m.hp, rp, m.p), new(big.Int).Exp(m.hq, rq, m.q))
	return &MintedRSW{N: new(big.Int).Set(m.N), X: x, ExpectedY: y, Iterations: m.Iterations}, nil
}

// ModulusHex returns N as zero-padded lowercase hex, as sent on the wire.
func (m *RSWMinter) ModulusHex() string { return paddedHex(m.N, m.modulusBytes) }

func (m *RSWMinter) crt(ap, aq *big.Int) *big.Int {
	delta := new(big.Int).Sub(ap, aq)
	delta.Mod(delta, m.p)
	delta.Mul(delta, m.qInvP)
	delta.Mod(delta, m.p)
	return new(big.Int).Add(aq, new(big.Int).Mul(m.q, delta))
}

// SolveRSW performs the t sequential squarings a client must do. It exists
// for tests and Go-side clients; it is deliberately slow.
func SolveRSW(modulus, x *big.Int, iterations int) *big.Int {
	result := new(big.Int).Mod(x, modulus)
	for i := 0; i < iterations; i++ {
		result.Mul(result, result)
		result.Mod(result, modulus)
	}
	return result
}

// VerifyRSW compares expected and claimed in constant time.
func VerifyRSW(expected, claimed *big.Int) bool {
	if expected == nil || claimed == nil || expected.Sign() < 0 || claimed.Sign() < 0 {
		return false
	}
	length := len(expected.Bytes())
	if l := len(claimed.Bytes()); l > length {
		length = l
	}
	if length == 0 {
		length = 1
	}
	want := expected.FillBytes(make([]byte, length))
	got := claimed.FillBytes(make([]byte, length))
	return subtle.ConstantTimeCompare(want, got) == 1
}

func verifyRSWHex(expectedHex, claimedHex string) bool {
	want, ok := parseHexInt(expectedHex)
	if !ok {
		return false
	}
	got, ok := parseHexInt(claimedHex)
	return ok && VerifyRSW(want, got)
}

func parseHexInt(value string) (*big.Int, bool) {
	value = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(value), "0x"), "0X")
	if value == "" {
		return nil, false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return nil, false
		}
	}
	parsed, ok := new(big.Int).SetString(value, 16)
	return parsed, ok
}

func paddedHex(value *big.Int, byteLength int) string {
	return fmt.Sprintf("%0*x", byteLength*2, value)
}

// randomIntRange returns a value in [2, modulus-2], matching capjs-core's
// generator selection (random mod (N-3) + 2).
func randomIntRange(random io.Reader, modulus *big.Int, byteLength int) (*big.Int, error) {
	raw := make([]byte, byteLength)
	if _, err := io.ReadFull(random, raw); err != nil {
		return nil, err
	}
	limit := new(big.Int).Sub(modulus, big.NewInt(3))
	value := new(big.Int).Mod(new(big.Int).SetBytes(raw), limit)
	return value.Add(value, big.NewInt(2)), nil
}
