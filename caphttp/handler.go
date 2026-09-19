// Package caphttp mounts a capgo.Cap on net/http with the exact wire
// contract the official @cap.js/widget expects:
//
//	POST {prefix}/challenge          → challenge JSON
//	POST {prefix}/redeem             → {"success":true,"token":...,"expires":...}
//	                                    or {"success":false,"error":"<reason>"}
//	POST {prefix}/{scope}/challenge  → scoped variants (optional)
//	POST {prefix}/{scope}/redeem
//
// Point the widget at the prefix: <cap-widget data-cap-api-endpoint="/api/cap/">.
package caphttp

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/zwh20081/capgo"
)

// Options configures the handler.
type Options struct {
	// MaxBodyBytes limits the redeem request body (default 64 KiB).
	MaxBodyBytes int64
	// Scopes is the allowlist for the {scope} path segment. Nil disables
	// scoped routes; an empty non-nil slice accepts any non-empty scope
	// (not recommended).
	Scopes []string
	// RequireScope rejects unscoped /challenge and /redeem calls.
	RequireScope bool
	// ChallengeOptions is invoked per request to customise the challenge
	// (for example difficulty by client IP). Scope is filled in first.
	ChallengeOptions func(r *http.Request, base capgo.ChallengeOptions) capgo.ChallengeOptions
	// ErrorLog receives storage and generation errors. Defaults to
	// log.Default().
	ErrorLog *log.Logger
}

// Handler serves the Cap widget endpoints.
type Handler struct {
	cap  *capgo.Cap
	opts Options
}

// New builds a handler.
func New(c *capgo.Cap, opts Options) *Handler {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 << 10
	}
	if opts.ErrorLog == nil {
		opts.ErrorLog = log.Default()
	}
	return &Handler{cap: c, opts: opts}
}

// Cap returns the underlying instance.
func (h *Handler) Cap() *capgo.Cap { return h.cap }

// Register mounts the routes on mux under prefix (e.g. "/api/cap"). Go 1.22
// pattern routing is used for the scoped variants.
func (h *Handler) Register(mux *http.ServeMux, prefix string) {
	prefix = strings.TrimSuffix(prefix, "/")
	mux.HandleFunc("POST "+prefix+"/challenge", h.Challenge)
	mux.HandleFunc("POST "+prefix+"/redeem", h.Redeem)
	if h.opts.Scopes != nil {
		mux.HandleFunc("POST "+prefix+"/{scope}/challenge", h.Challenge)
		mux.HandleFunc("POST "+prefix+"/{scope}/redeem", h.Redeem)
	}
}

// ServeHTTP routes by the trailing path segment so the handler can also be
// mounted with http.StripPrefix on older muxes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "error": "method_not_allowed"})
		return
	}
	path := strings.Trim(r.URL.Path, "/")
	segments := strings.Split(path, "/")
	action := segments[len(segments)-1]
	if len(segments) >= 2 && h.opts.Scopes != nil {
		r = r.WithContext(context.WithValue(r.Context(), scopeKey{}, segments[len(segments)-2]))
	}
	switch action {
	case "challenge":
		h.Challenge(w, r)
	case "redeem":
		h.Redeem(w, r)
	default:
		http.NotFound(w, r)
	}
}

type scopeKey struct{}

func (h *Handler) scope(r *http.Request) (string, bool) {
	scope := r.PathValue("scope")
	if scope == "" {
		if v, ok := r.Context().Value(scopeKey{}).(string); ok {
			scope = v
		}
	}
	if scope == "" {
		return "", !h.opts.RequireScope
	}
	if h.opts.Scopes == nil {
		return "", false
	}
	if len(h.opts.Scopes) == 0 {
		return scope, true
	}
	for _, allowed := range h.opts.Scopes {
		if allowed == scope {
			return scope, true
		}
	}
	return "", false
}

// Challenge handles POST .../challenge.
func (h *Handler) Challenge(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.scope(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid_scope"})
		return
	}
	opts := capgo.ChallengeOptions{Scope: scope}
	if h.opts.ChallengeOptions != nil {
		opts = h.opts.ChallengeOptions(r, opts)
	}
	challenge, err := h.cap.Challenge(r.Context(), opts)
	if err != nil {
		h.opts.ErrorLog.Printf("caphttp: challenge: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "challenge_failed"})
		return
	}
	writeJSON(w, http.StatusOK, challenge)
}

// Redeem handles POST .../redeem.
func (h *Handler) Redeem(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.scope(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "invalid_scope"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.opts.MaxBodyBytes)
	var req capgo.RedeemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": capgo.ReasonInvalidBody})
		return
	}
	token, err := h.cap.Redeem(r.Context(), req, capgo.RedeemOptions{Scope: scope})
	if err != nil {
		var pe *capgo.Error
		if errors.As(err, &pe) && pe.Cause == nil {
			body := map[string]any{"success": false, "error": pe.Reason}
			if pe.Instr {
				body["instr_error"] = true
			}
			writeJSON(w, http.StatusOK, body)
			return
		}
		h.opts.ErrorLog.Printf("caphttp: redeem: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "redeem_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "token": token.Token, "expires": token.Expires})
}

// Validate is a convenience for business handlers: it consumes the token
// (single use) and returns whether the request may proceed.
func (h *Handler) Validate(r *http.Request, token, scope string) (bool, error) {
	return h.cap.Validate(r.Context(), token, capgo.ValidateOptions{Scope: scope})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
