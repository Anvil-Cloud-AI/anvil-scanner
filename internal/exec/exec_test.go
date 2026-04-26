package exec

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRun_Success covers the happy path: a tiny command that exits 0.
// Using `echo` keeps the test portable across macOS and Linux, which
// are the only platforms anvil-scanner supports.
func TestRun_Success(t *testing.T) {
	res := Run("echo", "hello anvil")

	if !res.Success() {
		t.Fatalf("expected success, got exitCode=%d err=%v timedOut=%v",
			res.ExitCode, res.Err, res.TimedOut)
	}
	if !strings.Contains(res.Stdout, "hello anvil") {
		t.Errorf("stdout missing expected text: %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	if res.TimedOut {
		t.Errorf("unexpected timeout flag")
	}
}

// TestRun_NonZeroExit covers the "command ran but failed" branch. We
// use `sh -c "exit 42"` because it's portable and the exit code is
// predictable. anvil-scanner treats non-zero exit as signal-worthy
// but not necessarily fatal, so the contract is: Err is non-nil,
// ExitCode reflects the child's return, and Success() is false.
func TestRun_NonZeroExit(t *testing.T) {
	res := Run("sh", "-c", "exit 42")

	if res.Success() {
		t.Fatal("expected failure on exit 42")
	}
	if res.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", res.ExitCode)
	}
	if res.TimedOut {
		t.Errorf("unexpected timeout flag")
	}
	if res.Err == nil {
		t.Errorf("expected non-nil Err on non-zero exit")
	}
}

// TestRun_BinaryNotFound covers the "process never starts" branch.
// ExitCode should be -1 (our sentinel for "no process state") rather
// than panicking on a nil ProcessState.
func TestRun_BinaryNotFound(t *testing.T) {
	res := Run("this-binary-definitely-does-not-exist-" + runtime.GOOS)

	if res.Success() {
		t.Fatal("expected failure when binary not found")
	}
	if res.ExitCode != -1 {
		t.Errorf("expected ExitCode -1 for missing binary, got %d", res.ExitCode)
	}
	if res.Err == nil {
		t.Errorf("expected non-nil Err when binary missing")
	}
}

// TestRunCtx_Timeout covers the deadline-exceeded branch. We sleep
// for 5s under a 50ms deadline. The child should be killed and
// TimedOut should be true. This is the most important branch to
// lock down — callers rely on TimedOut to distinguish "child failed"
// from "we gave up waiting."
func TestRunCtx_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := RunCtx(ctx, nil, "sleep", "5")
	elapsed := time.Since(start)

	if !res.TimedOut {
		t.Errorf("expected TimedOut=true, got err=%v exitCode=%d", res.Err, res.ExitCode)
	}
	if res.Success() {
		t.Errorf("Success() must return false on timeout")
	}
	// Allow generous slack — CI hosts can be slow. If this takes
	// more than 2 seconds to kill a 5-second sleep, something is
	// wrong with the context-cancellation path.
	if elapsed > 2*time.Second {
		t.Errorf("timeout path took %v — child likely not killed promptly", elapsed)
	}
}

// TestRunCtx_Stdin verifies the stdin pipe actually reaches the
// child. We use `cat` which echoes stdin to stdout.
func TestRunCtx_Stdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := RunCtx(ctx, strings.NewReader("piped input"), "cat")

	if !res.Success() {
		t.Fatalf("expected cat to succeed, got %+v", res)
	}
	if res.Stdout != "piped input" {
		t.Errorf("expected stdout %q, got %q", "piped input", res.Stdout)
	}
}

// TestResult_Success covers the boolean-logic edges of Result.Success().
// Kept separate from the process-running tests so a regression in the
// flag logic is obvious from the failure name.
func TestResult_Success(t *testing.T) {
	tests := []struct {
		name string
		r    Result
		want bool
	}{
		{"clean exit 0", Result{ExitCode: 0}, true},
		{"non-zero exit", Result{ExitCode: 1}, false},
		{"timed out", Result{ExitCode: 0, TimedOut: true}, false},
		{"err set", Result{ExitCode: 0, Err: context.Canceled}, false},
		{"binary missing", Result{ExitCode: -1, Err: context.Canceled}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Success(); got != tc.want {
				t.Errorf("Success() = %v, want %v", got, tc.want)
			}
		})
	}
}
