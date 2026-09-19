package capgo

import (
	"errors"
	"fmt"
)

// Reason codes are stable strings mirroring capjs-core so that clients can
// branch on them. They are returned as the JSON "error"/"reason" field by
// package caphttp.
const (
	ReasonInvalidBody       = "invalid_body"
	ReasonMissingToken      = "missing_token"
	ReasonMissingSolutions  = "missing_solutions"
	ReasonInvalidToken      = "invalid_token"
	ReasonScopeMismatch     = "scope_mismatch"
	ReasonExpired           = "expired"
	ReasonInvalidSolutions  = "invalid_solutions"
	ReasonInvalidSolution   = "invalid_solution"
	ReasonAlreadyRedeemed   = "already_redeemed"
	ReasonNonceStoreError   = "nonce_store_error"
	ReasonInstrCorrupted    = "instr_corrupted"
	ReasonInstrExpired      = "instr_expired"
	ReasonInstrAutomated    = "instr_automated_browser"
	ReasonInstrTimeout      = "instr_timeout"
	ReasonInstrMissing      = "instr_missing"
	ReasonInstrFailed       = "instr_failed"
	ReasonChallengeNotFound = "challenge_invalid_or_expired"
)

// Error is a protocol-level rejection. Reason is one of the Reason* codes;
// Instr is true for instrumentation failures (capjs-core's instr_error flag).
type Error struct {
	Reason string
	Instr  bool
	Cause  error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("capgo: %s: %v", e.Reason, e.Cause)
	}
	return "capgo: " + e.Reason
}

func (e *Error) Unwrap() error { return e.Cause }

// Is lets errors.Is match on the reason: errors.Is(err, ErrExpired).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason
}

func fail(reason string) error { return &Error{Reason: reason} }

func failInstr(reason string) error { return &Error{Reason: reason, Instr: true} }

func storeErr(reason string, err error) error {
	return &Error{Reason: reason, Cause: errors.Join(ErrStore, err)}
}

// Sentinel values for errors.Is comparisons.
var (
	ErrInvalidBody       = &Error{Reason: ReasonInvalidBody}
	ErrMissingToken      = &Error{Reason: ReasonMissingToken}
	ErrMissingSolutions  = &Error{Reason: ReasonMissingSolutions}
	ErrInvalidToken      = &Error{Reason: ReasonInvalidToken}
	ErrScopeMismatch     = &Error{Reason: ReasonScopeMismatch}
	ErrExpired           = &Error{Reason: ReasonExpired}
	ErrInvalidSolutions  = &Error{Reason: ReasonInvalidSolutions}
	ErrInvalidSolution   = &Error{Reason: ReasonInvalidSolution}
	ErrAlreadyRedeemed   = &Error{Reason: ReasonAlreadyRedeemed}
	ErrNonceStore        = &Error{Reason: ReasonNonceStoreError}
	ErrInstrCorrupted    = &Error{Reason: ReasonInstrCorrupted, Instr: true}
	ErrInstrExpired      = &Error{Reason: ReasonInstrExpired, Instr: true}
	ErrInstrAutomated    = &Error{Reason: ReasonInstrAutomated, Instr: true}
	ErrInstrTimeout      = &Error{Reason: ReasonInstrTimeout, Instr: true}
	ErrInstrMissing      = &Error{Reason: ReasonInstrMissing, Instr: true}
	ErrInstrFailed       = &Error{Reason: ReasonInstrFailed, Instr: true}
	ErrChallengeNotFound = &Error{Reason: ReasonChallengeNotFound}
)

// ReasonOf extracts the reason code from an error, or "" for non-protocol
// errors.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
