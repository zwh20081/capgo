package capjs

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/zwh20081/capgo"
)

func TestGeneratorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g := NewInstrumentationGenerator(Options{NodePath: filepath.Join(t.TempDir(), "missing-node")})
	if result, err := g(ctx, nil, capgo.InstrumentationOptions{}, time.Now()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %v", result, err)
	}
}

func TestGeneratorMissingNode(t *testing.T) {
	g := NewInstrumentationGenerator(Options{NodePath: filepath.Join(t.TempDir(), "missing-node")})
	if result, err := g(context.Background(), nil, capgo.InstrumentationOptions{}, time.Now()); result != nil || err == nil {
		t.Fatalf("got %v, %v", result, err)
	}
}
