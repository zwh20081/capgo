// Package capjs provides optional Node.js-backed instrumentation with the
// official capjs-core generator, including its advanced obfuscation levels.
package capjs

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/zwh20081/capgo"
)

//go:embed generate.mjs
var runner string

// Options locates the caller-managed Node.js installation and npm packages.
type Options struct {
	// NodePath defaults to "node", resolved through PATH.
	NodePath string
	// ModuleDir is an absolute project directory containing node_modules with
	// capjs-core and its dependencies installed. Empty uses the working directory.
	ModuleDir string
}

// NewInstrumentationGenerator runs the official generator in a subprocess for
// each challenge. Levels 4-7 require esbuild; levels 8-10 additionally require
// javascript-obfuscator. Missing dependencies fail rather than weaken the level.
// Advanced levels preserve the dynamic eval probe while applying the upstream
// obfuscation profile to the rest of the script.
// Use a request deadline and bound challenge concurrency at the application edge.
// Entropy comes from Node.js crypto, not Cap.Options.Random.
func NewInstrumentationGenerator(opts Options) capgo.InstrumentationGenerator {
	if opts.NodePath == "" {
		opts.NodePath = "node"
	}
	return func(ctx context.Context, _ io.Reader, input capgo.InstrumentationOptions, now time.Time) (*capgo.Instrumentation, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		level := input.ObfuscationLevel
		if level == 0 {
			level = 3
		}
		level = max(1, min(10, level))
		ttl := input.TTL
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		body, err := json.Marshal(map[string]any{
			"blockAutomatedBrowsers": input.BlockAutomatedBrowsers,
			"obfuscationLevel":       level,
			"ttlMs":                  ttl.Milliseconds(),
		})
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, opts.NodePath, "--input-type=module", "-e", runner)
		cmd.WaitDelay = 5 * time.Second
		cmd.Dir = opts.ModuleDir
		cmd.Stdin = bytes.NewReader(body)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, fmt.Errorf("capjs: instrumentation: %w: %s", err, stderr.String())
		}
		var result struct {
			capgo.InstrumentationMeta
			Blob string `json:"instrumentation"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			return nil, fmt.Errorf("capjs: invalid generator response: %w", err)
		}
		result.Expires = now.Add(ttl).UnixMilli()
		return &capgo.Instrumentation{Blob: result.Blob, Meta: result.InstrumentationMeta}, nil
	}
}
