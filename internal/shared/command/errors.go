// Package command contains shared command execution errors and their process
// exit-code mapping.
package command

import (
	"errors"
	"fmt"

	"raxuiscli/internal/shared/constants"
)

var (
	// ErrOperational is the category marker for input and operational failures.
	ErrOperational = errors.New("operational failure")
	// ErrPolicyThreshold marks a completed operation whose findings crossed the
	// configured policy threshold.
	ErrPolicyThreshold = errors.New("policy threshold reached")
	// ErrOperationalFailure is a descriptive alias for ErrOperational.
	ErrOperationalFailure = ErrOperational
)

// OperationalError represents an invalid-input or operational failure. Cause
// is retained so callers can inspect the underlying error with errors.Is/As.
type OperationalError struct {
	Cause error
	// Err is retained as a convenient alias for callers constructing the type
	// directly. New code should use NewOperationalError.
	Err error
}

func (e *OperationalError) Error() string {
	if e == nil || e.cause() == nil {
		return ErrOperational.Error()
	}
	return e.cause().Error()
}

func (e *OperationalError) Unwrap() error {
	if e == nil || e.cause() == nil {
		return ErrOperational
	}
	return e.cause()
}

func (e *OperationalError) cause() error {
	if e == nil {
		return nil
	}
	if e.Cause != nil {
		return e.Cause
	}
	return e.Err
}

func (e *OperationalError) Is(target error) bool { return target == ErrOperational }

// NewOperationalError wraps an input or operational failure for exit-code
// mapping while preserving its cause.
func NewOperationalError(cause error) *OperationalError {
	return &OperationalError{Cause: cause}
}

// PolicyError indicates that a completed operation produced a finding at or
// above the configured threshold.
type PolicyError struct {
	Severity  constants.Severity
	Threshold constants.Severity
	Cause     error
}

func (e *PolicyError) Error() string {
	if e == nil {
		return ErrPolicyThreshold.Error()
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", ErrPolicyThreshold, e.Cause)
	}
	return fmt.Sprintf("finding severity %s meets threshold %s", e.Severity, e.Threshold)
}

func (e *PolicyError) Unwrap() error {
	if e != nil && e.Cause != nil {
		return e.Cause
	}
	return ErrPolicyThreshold
}

func (e *PolicyError) Is(target error) bool { return target == ErrPolicyThreshold }

// NewPolicyError creates an error for a finding that crossed a fail-on policy
// threshold.
func NewPolicyError(severity, threshold constants.Severity) *PolicyError {
	return &PolicyError{Severity: severity, Threshold: threshold}
}

// PolicyThresholdError is a descriptive alias for PolicyError.
type PolicyThresholdError = PolicyError

// NewPolicyThresholdError is an explicit alias for NewPolicyError.
func NewPolicyThresholdError(severity, threshold constants.Severity) *PolicyError {
	return NewPolicyError(severity, threshold)
}

// ExitCode maps command errors to the CLI contract: success is 0, operational
// failures are 1, and policy threshold failures are 2.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var policyErr *PolicyError
	if errors.As(err, &policyErr) || errors.Is(err, ErrPolicyThreshold) {
		return 2
	}
	return 1
}
