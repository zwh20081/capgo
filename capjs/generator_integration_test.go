//go:build integration

package capjs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zwh20081/capgo"
)

func TestOfficialGenerator(t *testing.T) {
	moduleDir, err := filepath.Abs("../internal/interop")
	if err != nil {
		t.Fatal(err)
	}
	g := NewInstrumentationGenerator(Options{ModuleDir: moduleDir})
	now := time.UnixMilli(1000)
	for _, level := range []int{0, 4, 8, 9, 10, 11} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, err := g(ctx, nil, capgo.InstrumentationOptions{ObfuscationLevel: level, TTL: time.Minute, BlockAutomatedBrowsers: true}, now)
		cancel()
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		if result.Blob == "" || result.Meta.ID == "" || len(result.Meta.Vars) != 4 || len(result.Meta.ExpectedVals) != 4 || result.Meta.Expires != 61000 || !result.Meta.BlockAutomatedBrowsers {
			t.Fatalf("level %d: invalid metadata %+v", level, result.Meta)
		}
	}
}

func fakeCore(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	core := filepath.Join(dir, "node_modules", "capjs-core")
	if err := os.MkdirAll(core, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"package.json":       `{"type":"module","main":"index.js"}`,
		"index.js":           "export {};",
		"instrumentation.js": script,
	} {
		if err := os.WriteFile(filepath.Join(core, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestOfficialGeneratorFailsWithoutAdvancedDependencies(t *testing.T) {
	dir := fakeCore(t, `throw new Error("generator should not be reached");`)
	g := NewInstrumentationGenerator(Options{ModuleDir: dir})
	for _, level := range []int{4, 8, 10} {
		_, err := g(context.Background(), nil, capgo.InstrumentationOptions{ObfuscationLevel: level}, time.Now())
		if err == nil || !strings.Contains(err.Error(), "esbuild") {
			t.Fatalf("level %d must fail for missing esbuild: %v", level, err)
		}
	}
	// With esbuild present, advanced levels must still require the obfuscator.
	esbuild := filepath.Join(dir, "node_modules", "esbuild")
	if err := os.MkdirAll(esbuild, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(esbuild, "index.js"), []byte("module.exports = {};"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := g(context.Background(), nil, capgo.InstrumentationOptions{ObfuscationLevel: 8}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "javascript-obfuscator") {
		t.Fatalf("must fail for missing obfuscator: %v", err)
	}
}

func TestOfficialGeneratorInterruptsProcess(t *testing.T) {
	dir := fakeCore(t, `export async function generateInstrumentation() { await new Promise(() => setInterval(() => {}, 1000)); }`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	g := NewInstrumentationGenerator(Options{ModuleDir: dir})
	start := time.Now()
	_, err := g(ctx, nil, capgo.InstrumentationOptions{}, time.Now())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("process cancellation: %v after %v", err, time.Since(start))
	}
}
