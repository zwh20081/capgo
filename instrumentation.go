package capgo

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// InstrumentationOptions controls the browser-environment challenge. The
// generated script is a port of capjs-core's generator: it runs in a sandboxed
// iframe, performs a set of randomized environment checks and evaluates a
// random arithmetic program whose result the server already knows.
type InstrumentationOptions struct {
	// BlockAutomatedBrowsers adds headless/webdriver detection. When a client
	// reports "blocked", redemption fails with ReasonInstrAutomated.
	BlockAutomatedBrowsers bool
	// ObfuscationLevel is 1..10 (default 3). Levels 1-3 only strip
	// whitespace. Levels 4+ additionally move every string literal into a
	// shuffled lookup table (capjs-core's fallback path when
	// javascript-obfuscator/esbuild are not installed).
	ObfuscationLevel int
	// TTL bounds how long the instrumentation result is accepted. Zero means
	// "same as the challenge TTL".
	TTL time.Duration
}

// InstrumentationMeta is the secret the server keeps (encrypted inside the
// challenge token) in order to verify a client's instrumentation result. The
// JSON shape matches capjs-core so tokens are interchangeable.
type InstrumentationMeta struct {
	ID                     string   `json:"id"`
	ExpectedVals           []int32  `json:"expectedVals"`
	Vars                   []string `json:"vars"`
	BlockAutomatedBrowsers bool     `json:"blockAutomatedBrowsers"`
	Expires                int64    `json:"expires,omitempty"`
}

// Instrumentation is a generated challenge: Blob goes to the client,
// Meta stays on the server.
type Instrumentation struct {
	Blob string
	Meta InstrumentationMeta
}

// InstrumentationResult is what the widget posts back ("instr" field).
type InstrumentationResult struct {
	I     string                     `json:"i"`
	State map[string]json.RawMessage `json:"state"`
	TS    int64                      `json:"ts,omitempty"`
}

const (
	ReasonInstrMissingMeta     = "missing_meta"
	ReasonInstrMissingOutput   = "missing_output"
	ReasonInstrIDMismatch      = "id_mismatch"
	ReasonInstrInvalidState    = "invalid_state"
	ReasonInstrInvalidMeta     = "invalid_meta"
	ReasonInstrFailedChallenge = "failed_challenge"
)

const defaultInstrumentationTTL = 5 * time.Minute

// ---- randomness helpers (crypto/rand backed) ----

func randInt(random io.Reader, lo, hi int) int { // inclusive
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(random, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		panic("capgo: random source failed: " + err.Error())
	}
	return lo + int(n.Int64())
}

func randHex(random io.Reader, length int) string {
	raw := make([]byte, (length+1)/2)
	if _, err := io.ReadFull(random, raw); err != nil {
		panic("capgo: random source failed: " + err.Error())
	}
	return hex.EncodeToString(raw)[:length]
}

const varLetters = "abcdefghijklmnopqrstuvwxyz"
const varChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randVar(random io.Reader, length int) string {
	if length == 0 {
		length = randInt(random, 4, 10)
	}
	var b strings.Builder
	b.WriteByte(varLetters[randInt(random, 0, 25)])
	for i := 1; i < length; i++ {
		b.WriteByte(varChars[randInt(random, 0, 35)])
	}
	return b.String()
}

func shuffleStrings(random io.Reader, items []string) {
	for i := len(items) - 1; i > 0; i-- {
		j := randInt(random, 0, i)
		items[i], items[j] = items[j], items[i]
	}
}

func hashWith(seed uint32) func(string) uint32 {
	return func(s string) uint32 { return fnv1a32Resume(seed, s) }
}

func jsonArray(v any) string {
	out, _ := json.Marshal(v)
	return string(out)
}

func jsString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(buf.String(), "\n")
}

// domSumMock mirrors the DOM-walking helper the client runs, using plain
// int32 arithmetic (JavaScript bit operators are int32).
func domSumMock(x, y, z int32) int32 {
	type node struct {
		parent *node
		value  int32
	}
	root := &node{}
	buildChain := func(parent *node, v int32) *node {
		cur := parent
		for i := 0; i < 8; i++ {
			child := &node{parent: cur, value: v}
			if v&1 == 0 {
				cur = child
			}
			v >>= 1
		}
		return cur
	}
	var walk func(n *node, sum int64) int64
	walk = func(n *node, sum int64) int64 {
		if n == nil || n == root {
			return sum % 256
		}
		return walk(n.parent, sum+int64(n.value))
	}
	return int32(walk(buildChain(buildChain(buildChain(root, x), y), z), 0))
}

var (
	windowPropMarkers = []string{"_Selenium_IDE_Recorder", "_selenium", "calledSelenium", "__webdriverFunc", "__lastWatirAlert", "__lastWatirConfirm", "__lastWatirPrompt", "_WEBDRIVER_ELEM_CACHE", "ChromeDriverw", "awesomium", "CefSharp", "RunPerfTest", "fmget_targets", "geb", "spawn", "domAutomation", "domAutomationController", "wdioElectron", "callPhantom", "_phantom", "__nightmare", "nightmare", "__playwright__binding__", "__pwInitScripts"}
	docPropMarkers    = []string{"__selenium_evaluate", "selenium-evaluate", "__selenium_unwrapped", "__webdriver_script_fn", "__driver_evaluate", "__webdriver_evaluate", "__fxdriver_evaluate", "__driver_unwrapped", "__webdriver_unwrapped", "__fxdriver_unwrapped", "__webdriver_script_func", "__webdriver_script_function"}
	navOwnPropMarkers = []string{"webdriver", "userAgent", "appVersion", "userAgentData", "platform", "vendor", "product", "productSub", "languages", "language", "plugins", "mimeTypes", "hardwareConcurrency", "deviceMemory", "maxTouchPoints", "permissions", "connection"}
	attrSubMarkers    = []string{"selenium", "webdriver", "driver"}
	stackSubMarkers   = []string{"pptr:", "UtilityScript.", "PhantomJS"}
	windowPrefixMark  = []string{"puppeteer_", "cdc_", "$cdc_"}
	uaTokenMarkers    = []string{"HeadlessChrome", "PhantomJS", "SlimerJS", "headless"}
)

func mapHash(h func(string) uint32, items []string) []uint32 {
	out := make([]uint32, len(items))
	for i, item := range items {
		out[i] = h(item)
	}
	return out
}

func buildBlockChecks(random io.Reader, b, id, hF, hSet string, h func(string) uint32) string {
	winHashes := jsonArray(mapHash(h, windowPropMarkers))
	docHashes := jsonArray(mapHash(h, docPropMarkers))
	navOwnHashes := jsonArray(mapHash(h, navOwnPropMarkers))
	attrSubHashes := jsonArray(mapHash(h, attrSubMarkers))
	stackSubHashes := jsonArray(mapHash(h, stackSubMarkers))
	winPrefixHashes := jsonArray(mapHash(h, windowPrefixMark))
	uaTokHashes := jsonArray(mapHash(h, uaTokenMarkers))
	webglVendorHash := h("Brian Paul")
	webglRendererHash := h("Mesa OffScreen")
	productSubGeckoHash := h("20030107")
	sequentumHash := h("Sequentum")

	var checks []string
	add := func(format string, args ...any) { checks = append(checks, fmt.Sprintf(format, args...)) }

	add(`if (!%[1]s) { try { var d = Object.getOwnPropertyDescriptors(navigator); var __wh = %[3]d; for (const k in d) { if (%[2]s(k) === __wh) { %[1]s = true; break; } } if (!%[1]s) { var p = Object.getPrototypeOf(navigator); while (p && !%[1]s) { for (const k of Object.getOwnPropertyNames(p)) { if (%[2]s(k) === __wh) { try { if (navigator[k]) %[1]s = true; } catch {} break; } } p = Object.getPrototypeOf(p); } } } catch { %[1]s = true; } }`, b, hF, h("webdriver"))
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[2]s = %[3]s; for (const k of Object.getOwnPropertyNames(navigator)) { if (%[4]s(%[2]s, %[5]s(k))) { %[1]s = true; break; } } } catch { %[1]s = true; } }`, b, a, navOwnHashes, hSet, hF)
	}
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { var %[2]s = %[3]s; for (const k of Object.getOwnPropertyNames(window)) { for (var pl = 4; pl <= 5; pl++) { if (%[4]s(%[2]s, %[5]s(k.slice(0, pl)))) { %[1]s = true; break; } } if (%[1]s) break; } }`, b, a, winPrefixHashes, hSet, hF)
	}
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { var %[2]s = %[3]s; for (const k of Object.getOwnPropertyNames(window)) { if (%[4]s(%[2]s, %[5]s(k))) { %[1]s = true; break; } } }`, b, a, winHashes, hSet, hF)
	}
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { var %[2]s = %[3]s; for (const k of Object.getOwnPropertyNames(document)) { if (%[4]s(%[2]s, %[5]s(k))) { %[1]s = true; break; } } }`, b, a, docHashes, hSet, hF)
	}
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[2]s = %[3]s; var an = document.documentElement.getAttributeNames(); for (const n of an) { for (const t of n.split(/[^a-z]+/i)) { if (t && %[4]s(%[2]s, %[5]s(t.toLowerCase()))) { %[1]s = true; break; } } if (%[1]s) break; } } catch { %[1]s = true; } }`, b, a, attrSubHashes, hSet, hF)
	}
	{
		a := randVar(random, 0)
		st := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[2]s = %[3]s; var %[6]s = (new Error()).stack || ''; for (var i = 0; i + 5 <= %[6]s.length; i++) { for (var sl = 5; sl <= 14; sl++) { if (i + sl > %[6]s.length) break; if (%[4]s(%[2]s, %[5]s(%[6]s.substr(i, sl)))) { %[1]s = true; break; } } if (%[1]s) break; } } catch {} }`, b, a, stackSubHashes, hSet, hF, st)
	}
	add(`if (!%[1]s) { try { if (typeof window.exposedFn !== 'undefined') { var s = window.exposedFn.toString(); for (var i = 0; i + 19 <= s.length; i++) { if (%[2]s(s.substr(i, 19)) === %[3]d) { %[1]s = true; break; } } } } catch {} }`, b, hF, h("exposeBindingHandle"))
	add(`if (!%[1]s && typeof window.process !== 'undefined') { try { if (%[2]s(window.process.type || '') === %[3]d || (window.process.versions && window.process.versions.electron)) %[1]s = true; } catch { %[1]s = true; } }`, b, hF, h("renderer"))
	{
		a := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[2]s = %[3]s; var ua = navigator.userAgent || ''; for (const t of ua.split(/[\s/(),;]/)) { if (t && %[4]s(%[2]s, %[5]s(t))) { %[1]s = true; break; } } if (!%[1]s) { var av = navigator.appVersion || ''; for (const t of av.split(/[\s/(),;]/)) { if (t && %[4]s(%[2]s, %[5]s(t))) { %[1]s = true; break; } } } } catch {} }`, b, a, uaTokHashes, hSet, hF)
	}
	add(`if (!%[1]s) { try { var c = document.createElement('canvas').getContext('webgl'); if (c) { var v = c.getParameter(c.VENDOR); var r = c.getParameter(c.RENDERER); if (%[2]s(v || '') === %[3]d && %[2]s(r || '') === %[4]d) %[1]s = true; } } catch {} }`, b, hF, webglVendorHash, webglRendererHash)
	add(`if (!%[1]s) { try { if (document.hasFocus && document.hasFocus() && window.outerWidth === 0 && window.outerHeight === 0) %[1]s = true; } catch { %[1]s = true; } }`, b)
	add(`if (!%[1]s) { try { var es = Function.prototype.toString.call(eval); var found = false; for (var i = 0; i + 13 <= es.length; i++) { if (%[2]s(es.substr(i, 13)) === %[3]d) { found = true; break; } } if (!found) %[1]s = true; } catch {} }`, b, hF, h("[native code]"))
	add(`if (!%[1]s) { try { if (typeof Function.prototype.bind === 'undefined') %[1]s = true; } catch {} }`, b)
	add(`if (!%[1]s) { try { if (window.external && typeof window.external.toString === 'function') { var s = window.external.toString(); for (var i = 0; i + 9 <= s.length; i++) { if (%[2]s(s.substr(i, 9)) === %[3]d) { %[1]s = true; break; } } } } catch { %[1]s = true; } }`, b, hF, sequentumHash)
	{
		ok := randVar(random, 0)
		i := randVar(random, 0)
		add(`if (!%[1]s) { try { if (navigator.mimeTypes) { var %[2]s = Object.getPrototypeOf(navigator.mimeTypes) === MimeTypeArray.prototype; for (var %[3]s = 0; %[3]s < navigator.mimeTypes.length && %[2]s; %[3]s++) { %[2]s = Object.getPrototypeOf(navigator.mimeTypes[%[3]s]) === MimeType.prototype; } if (!%[2]s) %[1]s = true; } } catch {} }`, b, ok, i)
	}
	{
		ua := randVar(random, 0)
		ps := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[3]s = navigator.productSub; var %[2]s = navigator.userAgent || ''; if (%[3]s && %[4]s(%[3]s) !== %[5]d) { var likeBlink = false; for (const t of %[2]s.toLowerCase().split(/[\s/(),;]/)) { var hh = %[4]s(t); if (hh === %[6]d || hh === %[7]d || hh === %[8]d) { likeBlink = true; break; } } if (likeBlink) %[1]s = true; } } catch {} }`, b, ua, ps, hF, productSubGeckoHash, h("chrome"), h("safari"), h("opera"))
	}
	{
		k := randVar(random, 0)
		add(`if (!%[1]s) { try { var %[2]s = Object.getOwnPropertyNames(window); for (const n of %[2]s) { var u = n.lastIndexOf('_'); if (u > 3 && u < n.length - 1) { var suf = n.slice(u + 1); var hh = %[3]s(suf); if (hh === %[4]d || hh === %[5]d || hh === %[6]d) { %[1]s = true; break; } } } } catch {} }`, b, k, hF, h("Array"), h("Promise"), h("Symbol"))
	}

	shuffleStrings(random, checks)
	sampled := checks
	if len(sampled) > 8 {
		sampled = sampled[:8]
	}
	return fmt.Sprintf(`let %[1]s = false;try {%[2]s} catch {%[1]s = true} if (%[1]s) {parent.postMessage({ type: 'cap:instr', nonce: %[3]s, result: '', blocked: true }, '*');return;}`, b, strings.Join(sampled, ""), jsString(id))
}

func buildClientScript(random io.Reader, id string, vars []string, initVals [4]int32, clientEqs string, blockAutomatedBrowsers bool) string {
	seed := uint32(randInt(random, 1, 0x7fffffff))
	h := hashWith(seed)
	hF := randVar(random, 0)
	hSet := randVar(random, 0)
	evalLocalVar := randVar(random, 0)
	evalSecret := randInt(random, 1_000_000, 0x7fffffff)
	evalA := randVar(random, 0)
	evalB := randVar(random, 0)
	evalC := randVar(random, 0)
	helpers := fmt.Sprintf(`function %[1]s(s){let h=%[3]d>>>0;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=(h+(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))>>>0;}return h>>>0;}`+
		`function %[2]s(a,v){for(var i=0;i<a.length;i++)if(a[i]===v)return true;return false;}`, hF, hSet, seed)

	blockChecks := ""
	if blockAutomatedBrowsers {
		blockChecks = buildBlockChecks(random, randVar(random, 0), id, hF, hSet, h)
	}

	dvKey := randVar(random, 0)
	nKey := randVar(random, 0)
	outKey := randVar(random, 0)

	leak1 := jsonArray(mapHash(h, []string{"Bun", "process", "module", "require", "global", "__dirname", "Deno"}))
	leak2 := jsonArray(mapHash(h, []string{"Bun", "process", "require", "global", "__dirname", "Deno"}))

	envChecks := []string{
		fmt.Sprintf(`try { const %[1]sst = (new Error()).stack || ''; if (%[1]sst.indexOf('node:internal') !== -1 || %[1]sst.indexOf('moduleEvaluation') !== -1 || %[1]sst.indexOf('loadAndEvaluateModule') !== -1 || %[1]sst.indexOf('file:///') !== -1 || %[1]sst.indexOf('[eval]') !== -1 || /\(native:/.test(%[1]sst)) return null; } catch { return null }`, nKey),

		`if (typeof HTMLElement !== 'function' || typeof Window !== 'function' || typeof Document !== 'function' || typeof Navigator !== 'function' || typeof Node !== 'function') return null; if (!(navigator instanceof Navigator) || !(document instanceof Document) || !(window instanceof Window) || !(document.body instanceof HTMLElement)) return null; if (globalThis !== window || window.self !== window || document.defaultView !== window) return null;`,

		fmt.Sprintf(`try { const %[1]sots = Object.prototype.toString; if (%[2]s(%[1]sots.call(navigator)) !== %[3]d || %[2]s(%[1]sots.call(window)) !== %[4]d || %[2]s(%[1]sots.call(document)) !== %[5]d) return null; } catch { return null }`, nKey, hF, h("[object Navigator]"), h("[object Window]"), h("[object HTMLDocument]")),

		fmt.Sprintf(`try { if (typeof EventTarget !== 'function' || !(document.body instanceof EventTarget) || !(window instanceof EventTarget)) return null; const %[1]sprobe = document.createElement('div'); let %[1]sfired = 0; const %[1]sev = '_c' + (Date.now() & 0xffff).toString(36); const %[1]sh = (e) => { if (e && e.detail === 0xc0de) %[1]sfired++; }; %[1]sprobe.addEventListener(%[1]sev, %[1]sh); %[1]sprobe.dispatchEvent(new CustomEvent(%[1]sev, { detail: 0xc0de })); %[1]sprobe.dispatchEvent(new CustomEvent(%[1]sev, { detail: 0xc0de })); %[1]sprobe.removeEventListener(%[1]sev, %[1]sh); %[1]sprobe.dispatchEvent(new CustomEvent(%[1]sev, { detail: 0xc0de })); if (%[1]sfired !== 2) return null; } catch { return null }`, nKey),

		fmt.Sprintf(`try { const %[1]sgf = new Function('return this'); const %[1]stg = %[1]sgf(); if (%[1]stg !== globalThis) return null; const %[1]sleakHashes = %[2]s; for (const %[1]sk of Object.getOwnPropertyNames(%[1]stg)) { if (%[3]s(%[1]sleakHashes, %[4]s(%[1]sk))) return null; } const %[1]sfnArgs = new Function('a','b','c','return a+b+c'); if (%[1]sfnArgs.length !== 3) return null; if (%[1]sfnArgs(10,20,30) !== 60) return null; const %[1]ssrc = Function.prototype.toString.call(%[1]sfnArgs); if (%[1]ssrc.indexOf('return a+b+c') === -1) return null; if (%[1]ssrc.indexOf('apply') !== -1 || %[1]ssrc.indexOf('callArgs') !== -1 || %[1]ssrc.indexOf('Reflect.') !== -1) return null; let %[1]sthrown = null; try { new Function('throw new Error("x")')(); } catch (%[1]se) { %[1]sthrown = %[1]se; } if (!%[1]sthrown || !%[1]sthrown.stack) return null; const %[1]sst2 = %[1]sthrown.stack; if (%[1]sst2.indexOf('node:internal') !== -1 || %[1]sst2.indexOf('moduleEvaluation') !== -1 || %[1]sst2.indexOf('file:///') !== -1 || %[1]sst2.indexOf('[eval]') !== -1 || /\(native:/.test(%[1]sst2)) return null; } catch { return null }`, nKey, leak1, hSet, hF),

		fmt.Sprintf(`try { const %[1]sie = (0, eval); const %[1]seg = %[1]sie('this'); if (%[1]seg !== globalThis) return null; const %[1]sleak2 = %[2]s; for (const %[1]sk of Object.getOwnPropertyNames(%[1]seg)) { if (%[3]s(%[1]sleak2, %[4]s(%[1]sk))) return null; } } catch { return null }`, nKey, leak2, hSet, hF),

		fmt.Sprintf(`try { var %[1]s = %[2]d; var %[3]s = '%[6]s'; var %[4]s = '%[7]s'; var %[5]s = %[3]s + %[4]s; var %[1]sr1 = (0, eval)('typeof ' + %[5]s); if (%[1]sr1 !== 'undefined') return null; var %[1]sr2 = eval(%[5]s); if (%[1]sr2 !== %[2]d) return null; var %[1]sr3 = eval(%[3]s + %[4]s + '+1'); if (%[1]sr3 !== %[8]d) return null; var %[1]sarr = ['(', '(', ')', '=', '>', 't', 'h', 'i', 's', ')', '(', ')']; var %[1]sarrow = (0, eval)(%[1]sarr.join('')); if (%[1]sarrow !== globalThis) return null; var %[1]sr4 = eval('(function(){return ' + %[5]s + '*2;})()'); if (%[1]sr4 !== %[9]d) return null; } catch { return null }`,
			evalLocalVar, evalSecret, evalA, evalB, evalC, evalLocalVar[:2], evalLocalVar[2:], evalSecret+1, evalSecret*2),
	}
	shuffleStrings(random, envChecks)

	return fmt.Sprintf(`(function(){window.onload=async function(){try {%[1]sconst %[2]s=await (async function(){%[3]s%[4]s
      var %[5]s=%[9]d;var %[6]s=%[10]d;var %[7]s=%[11]d;var %[8]s=%[12]d;%[13]s
      var %[14]s={};%[14]s["%[5]s"]=%[5]s;%[14]s["%[6]s"]=%[6]s;%[14]s["%[7]s"]=%[7]s;%[14]s["%[8]s"]=%[8]s;return %[14]s;})();if (!%[2]s || typeof %[2]s !== 'object') return;parent.postMessage({type: 'cap:instr',nonce:%[15]s,result:{i:%[15]s,state:%[2]s,ts:Date.now()}},'*');} catch {}};})();`,
		helpers, dvKey, strings.Join(envChecks, ""), blockChecks,
		vars[0], vars[1], vars[2], vars[3],
		initVals[0], initVals[1], initVals[2], initVals[3],
		clientEqs, outKey, jsString(id))
}

// GenerateInstrumentation builds a fresh instrumentation challenge. It is
// exported for callers embedding the blob in their own token format; Cap
// calls it automatically when instrumentation is enabled.
func GenerateInstrumentation(random io.Reader, opts InstrumentationOptions, now time.Time) (*Instrumentation, error) {
	if random == nil {
		random = rand.Reader
	}
	id := randHex(random, 32)
	vars := make([]string, 4)
	for i := range vars {
		vars[i] = randVar(random, 12)
	}
	var initVals [4]int32
	for i := range initVals {
		initVals[i] = int32(randInt(random, 10, 250))
	}
	vals := initVals

	correctKey := int32(randInt(random, 1000, 9000))
	badKey := correctKey
	for badKey == correctKey {
		badKey = int32(randInt(random, 1000, 9000))
	}
	vals[0] ^= correctKey

	fnHelper := randVar(random, 0)
	domHelper := randVar(random, 0)
	helperDecls := fmt.Sprintf(`function %[1]s(a,b,c){function F(d){this.v=function(){return this.k^d;}};var p={k:c};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}`+
		`function %[2]s(x,y,z){var d=document.createElement('div');d.style.display='none';document.body.appendChild(d);function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}function B(n,r,s){if(!n||n==r)return s%%256;while(n.children.length>0)n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}`, fnHelper, domHelper)

	var eqs strings.Builder
	eqs.WriteString(helperDecls)
	fmt.Fprintf(&eqs, `%s = %s ^ (navigator.userAgent ? %d : %d);`, vars[0], vars[0], correctKey, badKey)

	for i := 0; i < 20; i++ {
		op := randInt(random, 0, 5)
		dest := randInt(random, 0, 3)
		src1 := randInt(random, 0, 3)
		src2 := randInt(random, 0, 3)
		src3 := randInt(random, 0, 3)
		vD, vS1, vS2, vS3 := vars[dest], vars[src1], vars[src2], vars[src3]
		switch op {
		case 0:
			fmt.Fprintf(&eqs, `%s = ~(%s & %s);`, vD, vD, vS1)
			vals[dest] = ^(vals[dest] & vals[src1])
		case 1:
			fmt.Fprintf(&eqs, `%s = %s ^ %s;`, vD, vD, vS1)
			vals[dest] ^= vals[src1]
		case 2:
			fmt.Fprintf(&eqs, `%s = %s | %s;`, vD, vD, vS1)
			vals[dest] |= vals[src1]
		case 3:
			fmt.Fprintf(&eqs, `%s = %s & %s;`, vD, vD, vS1)
			vals[dest] &= vals[src1]
		case 4:
			fmt.Fprintf(&eqs, `%s = %s(%s, %s, %s);`, vD, fnHelper, vS1, vS2, vD)
			vals[dest] = (vals[src2] ^ vals[src1]) | (vals[dest] ^ vals[src2])
		default:
			fmt.Fprintf(&eqs, `%s = %s(%s, %s, %s);`, vD, domHelper, vS1, vS2, vS3)
			vals[dest] = domSumMock(vals[src1], vals[src2], vals[src3])
		}
	}

	for i := 0; i < 4; i++ {
		salt := int32(randInt(random, 100_000, 999_999))
		fmt.Fprintf(&eqs, `%s=((%s^%d)&0x7FFFFFFF)%%900000+100000;`, vars[i], vars[i], salt)
		vals[i] = ((vals[i]^salt)&0x7FFFFFFF)%900_000 + 100_000
	}

	script := buildClientScript(random, id, vars, initVals, eqs.String(), opts.BlockAutomatedBrowsers)

	level := opts.ObfuscationLevel
	if level == 0 {
		level = 3
	}
	if level < 1 {
		level = 1
	}
	if level > 10 {
		level = 10
	}
	var finalScript string
	if level <= 3 {
		finalScript = stripScriptWhitespace(script)
	} else {
		finalScript = stripScriptWhitespace(obfuscateStrings(random, script))
	}

	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write([]byte(finalScript)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultInstrumentationTTL
	}
	return &Instrumentation{
		Blob: base64.StdEncoding.EncodeToString(compressed.Bytes()),
		Meta: InstrumentationMeta{
			ID: id, ExpectedVals: vals[:], Vars: vars,
			BlockAutomatedBrowsers: opts.BlockAutomatedBrowsers,
			Expires:                now.UnixMilli() + ttl.Milliseconds(),
		},
	}, nil
}

var (
	reNewlineSpace = regexp.MustCompile(`\n\s*`)
	reLeadingSpace = regexp.MustCompile(`(?m)^\s+`)
)

func stripScriptWhitespace(script string) string {
	return reLeadingSpace.ReplaceAllString(reNewlineSpace.ReplaceAllString(script, "\n"), "")
}

// obfuscateStrings hoists every string literal into a shuffled array, like
// capjs-core's customObfuscateStrings.
func obfuscateStrings(random io.Reader, script string) string {
	type literal struct {
		start, end int
		value      string
	}
	var literals []literal
	for i := 0; i < len(script); {
		quote := script[i]
		if quote != '\'' && quote != '"' {
			i++
			continue
		}
		j := i + 1
		var body strings.Builder
		closed := false
		for j < len(script) {
			c := script[j]
			if c == '\\' && j+1 < len(script) && script[j+1] != '\n' {
				body.WriteByte(c)
				body.WriteByte(script[j+1])
				j += 2
				continue
			}
			if c == quote {
				closed = true
				break
			}
			body.WriteByte(c)
			j++
		}
		if !closed {
			i++
			continue
		}
		value, ok := decodeJSString(quote, body.String())
		if !ok {
			i++
			continue
		}
		literals = append(literals, literal{start: i, end: j + 1, value: value})
		i = j + 1
	}
	if len(literals) == 0 {
		return script
	}
	index := map[string]int{}
	var values []string
	for _, lit := range literals {
		if _, seen := index[lit.value]; !seen {
			index[lit.value] = len(values)
			values = append(values, lit.value)
		}
	}
	shuffleStrings(random, values)
	for i, v := range values {
		index[v] = i
	}
	tName := "_T" + randHex(random, 6)
	var out strings.Builder
	last := 0
	for _, lit := range literals {
		out.WriteString(script[last:lit.start])
		fmt.Fprintf(&out, "%s[%d]", tName, index[lit.value])
		last = lit.end
	}
	out.WriteString(script[last:])
	var table bytes.Buffer
	enc := json.NewEncoder(&table)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(values)
	return "var " + tName + "=" + strings.TrimRight(table.String(), "\n") + ";" + out.String()
}

// decodeJSString turns the raw body of a JS string literal into its value
// by routing it through JSON, exactly like capjs-core does.
func decodeJSString(quote byte, body string) (string, bool) {
	var safe strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body):
			safe.WriteByte(c)
			safe.WriteByte(body[i+1])
			i++
		case c == '"':
			safe.WriteString(`\"`)
		default:
			safe.WriteByte(c)
		}
	}
	text := safe.String()
	if quote == '\'' {
		text = strings.ReplaceAll(text, `\'`, `'`)
	}
	var value string
	if err := json.Unmarshal([]byte(`"`+text+`"`), &value); err != nil {
		return "", false
	}
	return value, true
}

// VerifyInstrumentationResult checks the client's reported program state
// against the server-side meta. A nil error means the result is valid.
func VerifyInstrumentationResult(meta *InstrumentationMeta, result json.RawMessage) error {
	if meta == nil || meta.ID == "" {
		return failInstr(ReasonInstrMissingMeta)
	}
	if len(bytes.TrimSpace(result)) == 0 || bytes.TrimSpace(result)[0] != '{' {
		return failInstr(ReasonInstrMissingOutput)
	}
	var payload InstrumentationResult
	if err := json.Unmarshal(result, &payload); err != nil {
		return failInstr(ReasonInstrMissingOutput)
	}
	if payload.I != meta.ID {
		return failInstr(ReasonInstrIDMismatch)
	}
	if payload.State == nil {
		return failInstr(ReasonInstrInvalidState)
	}
	if len(meta.Vars) == 0 || len(meta.Vars) != len(meta.ExpectedVals) {
		return failInstr(ReasonInstrInvalidMeta)
	}
	for i, name := range meta.Vars {
		raw, ok := payload.State[name]
		if !ok {
			return failInstr(ReasonInstrFailedChallenge)
		}
		var actual float64
		if err := json.Unmarshal(raw, &actual); err != nil || actual != float64(meta.ExpectedVals[i]) {
			return failInstr(ReasonInstrFailedChallenge)
		}
	}
	return nil
}

// checkInstrumentation applies capjs-core's redeem-time rules to a client
// submission (result, blocked flag, timeout flag).
func checkInstrumentation(meta *InstrumentationMeta, now int64, result json.RawMessage, blocked, timeout bool) error {
	if meta == nil {
		return failInstr(ReasonInstrCorrupted)
	}
	if meta.Expires != 0 && now > meta.Expires {
		return failInstr(ReasonInstrExpired)
	}
	switch {
	case blocked:
		if meta.BlockAutomatedBrowsers {
			return failInstr(ReasonInstrAutomated)
		}
		return nil
	case timeout:
		return failInstr(ReasonInstrTimeout)
	case len(bytes.TrimSpace(result)) > 0 && string(bytes.TrimSpace(result)) != "null" && string(bytes.TrimSpace(result)) != "false":
		return VerifyInstrumentationResult(meta, result)
	default:
		return failInstr(ReasonInstrMissing)
	}
}
