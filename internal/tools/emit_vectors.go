//go:build ignore

// Emits challenges + solutions produced by capgo so a Node script can validate
// them with the official capjs-core package (reverse interoperability check).
//
//	go run ./internal/tools/emit_vectors.go > vectors.json
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/zwh20081/capgo"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func main() {
	secret := bytes.Repeat([]byte{0x42}, 32)
	kp := must(capgo.GenerateRSWKeypair(rand.Reader, 2048))
	now := time.Now()
	fixed := func() time.Time { return now }
	out := map[string]any{"secretHex": fmt.Sprintf("%x", secret), "keypair": kp}

	c1 := must(capgo.New(capgo.Options{Secret: secret, Stateless: true, ChallengeCount: 2, ChallengeDifficulty: 1, Now: fixed}))
	ch1 := must(c1.Challenge(context.Background(), capgo.ChallengeOptions{Scope: "login"}))
	out["format1"] = map[string]any{"scope": "login", "challenge": ch1, "solutions": must(capgo.SolveChallenge(ch1))}

	c2 := must(capgo.New(capgo.Options{Secret: secret, Format: 2, Protocols: []capgo.Protocol{capgo.ProtocolSHA256PoW, capgo.ProtocolRSW}, RSWKeypair: kp, RSWIterations: 3000, ChallengeCount: 2, ChallengeSize: 8, ChallengeDifficulty: 1, Now: fixed}))
	ch2 := must(c2.Challenge(context.Background(), capgo.ChallengeOptions{Scope: "signup"}))
	out["format2"] = map[string]any{"scope": "signup", "challenge": ch2, "solutions": must(capgo.SolveChallenge(ch2))}

	var instrs []any
	for _, block := range []bool{false, true} {
		for _, level := range []int{3, 6} {
			in := must(capgo.GenerateInstrumentation(rand.Reader, capgo.InstrumentationOptions{BlockAutomatedBrowsers: block, ObfuscationLevel: level, TTL: time.Minute}, now))
			instrs = append(instrs, map[string]any{"block": block, "level": level, "blob": in.Blob, "meta": in.Meta})
		}
	}
	out["instrumentation"] = instrs

	c3 := must(capgo.New(capgo.Options{Secret: secret, Stateless: true, ChallengeCount: 1, ChallengeDifficulty: 1, Instrumentation: &capgo.InstrumentationOptions{}, Now: fixed}))
	ch3 := must(c3.Challenge(context.Background(), capgo.ChallengeOptions{Scope: "fb"}))
	out["format1instr"] = map[string]any{"scope": "fb", "challenge": ch3, "solutions": must(capgo.SolveChallenge(ch3))}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	must(0, enc.Encode(out))
}
