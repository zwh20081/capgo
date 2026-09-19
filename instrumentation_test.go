package capgo

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
)

func inflateBlob(t *testing.T, blob string) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	script, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		t.Fatal(err)
	}
	return string(script)
}

func TestGenerateInstrumentationShape(t *testing.T) {
	for _, level := range []int{1, 3, 5, 10} {
		for _, block := range []bool{false, true} {
			instr, err := GenerateInstrumentation(rand.Reader, InstrumentationOptions{BlockAutomatedBrowsers: block, ObfuscationLevel: level, TTL: time.Minute}, time.UnixMilli(1000))
			if err != nil {
				t.Fatal(err)
			}
			if len(instr.Meta.ID) != 32 || len(instr.Meta.Vars) != 4 || len(instr.Meta.ExpectedVals) != 4 || instr.Meta.Expires != 61000 {
				t.Fatalf("meta = %+v", instr.Meta)
			}
			for _, v := range instr.Meta.ExpectedVals {
				if v < 100_000 || v > 999_999 {
					t.Fatalf("expected value out of range: %d", v)
				}
			}
			script := inflateBlob(t, instr.Blob)
			if !strings.Contains(script, "cap:instr") || !strings.Contains(script, "window.onload") {
				t.Fatalf("level %d: script missing markers: %.120s", level, script)
			}
			if level > 3 && !strings.Contains(script, "var _T") {
				t.Fatalf("level %d: string table missing", level)
			}
			if block != strings.Contains(script, "blocked: true") && block != strings.Contains(script, "blocked:true") {
				t.Fatalf("level %d block=%v: block checks mismatch", level, block)
			}
			if !strings.Contains(script, instr.Meta.ID) {
				t.Fatal("script must embed id")
			}
			// The script must not leak expected values.
			for _, v := range instr.Meta.ExpectedVals {
				if regexp.MustCompile(`\b` + jsNumberString(float64(v)) + `\b`).MatchString(script) {
					t.Fatalf("expected value %d appears in script", v)
				}
			}
		}
	}
}

func TestObfuscateStringsPreservesSemantics(t *testing.T) {
	src := `var a = 'it\'s'; var b = "q\"x"; var c = 'plain'; var d = "plain"; f('\\n', "é");`
	out := obfuscateStrings(rand.Reader, src)
	if !strings.HasPrefix(out, "var _T") {
		t.Fatalf("out = %s", out)
	}
	tableJSON := out[strings.Index(out, "=")+1 : strings.Index(out, ";")]
	var table []string
	if err := json.Unmarshal([]byte(tableJSON), &table); err != nil {
		t.Fatalf("table %s: %v", tableJSON, err)
	}
	want := map[string]bool{"it's": true, `q"x`: true, "plain": true, `\n`: true, "é": true}
	if len(table) != len(want) {
		t.Fatalf("table = %v", table)
	}
	for _, v := range table {
		if !want[v] {
			t.Fatalf("unexpected table entry %q", v)
		}
	}
	if strings.Contains(out[strings.Index(out, ";"):], "'plain'") {
		t.Fatal("literal not replaced")
	}
}

func TestDomSumMockMatchesJavaScript(t *testing.T) {
	// Values computed with capjs-core's domSumMock in Node.
	cases := []struct{ x, y, z, want int32 }{
		{10, 20, 30, 74}, {255, 255, 255, 0}, {100, 200, 50, 92}, {12345, -7, 9999, 214},
	}
	for _, tc := range cases {
		if got := domSumMock(tc.x, tc.y, tc.z); got != tc.want {
			t.Fatalf("domSumMock(%d,%d,%d) = %d want %d", tc.x, tc.y, tc.z, got, tc.want)
		}
	}
}

func TestCheckInstrumentationRules(t *testing.T) {
	meta := &InstrumentationMeta{ID: "id", Vars: []string{"a"}, ExpectedVals: []int32{5}, BlockAutomatedBrowsers: true, Expires: 100}
	good := json.RawMessage(`{"i":"id","state":{"a":5}}`)
	cases := []struct {
		name          string
		meta          *InstrumentationMeta
		now           int64
		result        json.RawMessage
		blocked, tout bool
		want          string
	}{
		{"ok", meta, 50, good, false, false, ""},
		{"nil meta", nil, 50, good, false, false, ReasonInstrCorrupted},
		{"expired", meta, 101, good, false, false, ReasonInstrExpired},
		{"blocked+block", meta, 50, nil, true, false, ReasonInstrAutomated},
		{"blocked no block", &InstrumentationMeta{ID: "id", Vars: []string{"a"}, ExpectedVals: []int32{5}}, 50, nil, true, false, ""},
		{"timeout", meta, 50, nil, false, true, ReasonInstrTimeout},
		{"missing", meta, 50, nil, false, false, ReasonInstrMissing},
		{"null", meta, 50, json.RawMessage(`null`), false, false, ReasonInstrMissing},
		{"id mismatch", meta, 50, json.RawMessage(`{"i":"x","state":{"a":5}}`), false, false, ReasonInstrIDMismatch},
		{"no state", meta, 50, json.RawMessage(`{"i":"id"}`), false, false, ReasonInstrInvalidState},
		{"wrong", meta, 50, json.RawMessage(`{"i":"id","state":{"a":6}}`), false, false, ReasonInstrFailedChallenge},
		{"not object", meta, 50, json.RawMessage(`"str"`), false, false, ReasonInstrMissingOutput},
	}
	for _, tc := range cases {
		err := checkInstrumentation(tc.meta, tc.now, tc.result, tc.blocked, tc.tout)
		if ReasonOf(err) != tc.want {
			t.Fatalf("%s: err = %v want %q", tc.name, err, tc.want)
		}
	}
}

func TestFormat1StatefulInstrumentationFlow(t *testing.T) {
	c := newTestCap(t, func(o *Options) {
		o.Secret = nil
		o.Instrumentation = &InstrumentationOptions{}
	})
	ch, err := c.Challenge(context.Background(), ChallengeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Instrumentation == "" {
		t.Fatal("instrumentation blob missing")
	}
	solutions, _ := SolveChallenge(ch)
	if err := redeemErr(c, RedeemRequest{Token: ch.Token, Solutions: solutions}, ""); ReasonOf(err) != ReasonInstrMissing {
		t.Fatalf("err = %v", err)
	}
	// Recover meta from the store and answer correctly.
	ch, _ = c.Challenge(context.Background(), ChallengeOptions{})
	solutions, _ = SolveChallenge(ch)
	store := c.Store().(*MemoryStore)
	store.mu.Lock()
	meta := store.challenges[ch.Token].Instr
	store.mu.Unlock()
	if _, err := c.Redeem(context.Background(), RedeemRequest{Token: ch.Token, Solutions: solutions, Instr: goodInstrResult(meta)}, RedeemOptions{}); err != nil {
		t.Fatal(err)
	}
}

func goodInstrResult(meta *InstrumentationMeta) json.RawMessage {
	state := map[string]int32{}
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}
	out, _ := json.Marshal(map[string]any{"i": meta.ID, "state": state, "ts": 1})
	return out
}

func TestFormat2InstrumentationAutoAppended(t *testing.T) {
	c := newTestCap(t, func(o *Options) {
		o.Format = 2
		o.Protocols = []Protocol{ProtocolSHA256PoW}
		o.ChallengeCount = 1
		o.Instrumentation = &InstrumentationOptions{BlockAutomatedBrowsers: true}
	})
	ch, err := c.Challenge(context.Background(), ChallengeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Challenges) != 2 || ch.Challenges[1].Protocol != ProtocolInstrumentation {
		t.Fatalf("challenges = %+v", ch.Challenges)
	}
	if _, ok := ch.Challenges[1].Payload.(InstrumentationPayload); !ok {
		t.Fatalf("payload = %#v", ch.Challenges[1].Payload)
	}
	if _, err := SolveChallenge(ch); err == nil {
		t.Fatal("SolveChallenge must refuse instrumentation")
	}
	pow := ch.Challenges[0].Payload.(PoWPayload)
	body, _ := json.Marshal([]any{map[string]any{"nonce": SolvePoW(pow.Salt, pow.Target)}, map[string]any{"blocked": true}})
	if err := redeemErr(c, RedeemRequest{Token: ch.Token, Solutions: body}, ""); ReasonOf(err) != ReasonInstrAutomated {
		t.Fatalf("err = %v", err)
	}
	ch2, _ := c.Challenge(context.Background(), ChallengeOptions{DisableInstrumentation: true})
	if len(ch2.Challenges) != 1 {
		t.Fatalf("DisableInstrumentation ignored: %+v", ch2.Challenges)
	}
}
