package command

import (
	"errors"
	"testing"

	"raxuiscli/internal/shared/constants"
)

func TestExitCodeOperationalError(t *testing.T) {
	cause := errors.New("request failed")
	err := NewOperationalError(cause)

	if got := ExitCode(err); got != 1 {
		t.Fatalf("ExitCode(operational error) = %d, want 1", got)
	}
	if !errors.Is(err, cause) {
		t.Error("operational error does not unwrap its cause")
	}
	if !errors.Is(err, ErrOperational) {
		t.Error("operational error does not match ErrOperational")
	}
	var target *OperationalError
	if !errors.As(err, &target) {
		t.Error("operational error does not support errors.As")
	}
}

func TestExitCodePolicyThresholdError(t *testing.T) {
	err := NewPolicyError(constants.SeverityHigh, constants.SeverityMedium)

	if got := ExitCode(err); got != 2 {
		t.Fatalf("ExitCode(policy error) = %d, want 2", got)
	}
	if !errors.Is(err, ErrPolicyThreshold) {
		t.Error("policy error does not match ErrPolicyThreshold")
	}
	var target *PolicyError
	if !errors.As(err, &target) {
		t.Error("policy error does not support errors.As")
	}
}

func TestExitCodeNilAndUnknownErrors(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", got)
	}
	if got := ExitCode(errors.New("invalid input")); got != 1 {
		t.Errorf("ExitCode(unknown error) = %d, want 1", got)
	}
}
