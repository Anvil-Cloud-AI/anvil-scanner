// Package exec wraps os/exec with the timeout, stdout/stderr, and
// return-code shape the scanner expects. It corresponds to the
// run_cmd() helper in python/anvil_scanner/core.py.
//
// All subprocess invocations in anvil-scanner go through this
// package so timeout handling, redaction, and logging stay uniform.
package exec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// DefaultTimeout mirrors the Python run_cmd() default (30s). Callers
// that need a different ceiling should pass it explicitly via RunCtx.
const DefaultTimeout = 30 * time.Second

// maxExecOutputBytes caps stdout and stderr independently at 1 MiB each to
// prevent runaway subprocesses from exhausting process memory.
const maxExecOutputBytes = 1 * 1024 * 1024

// limitedWriter wraps bytes.Buffer with a hard capacity cap.  Bytes beyond
// the cap are silently discarded; the Write call always reports consuming
// all of p so the child process does not receive a broken-pipe error.
type limitedWriter struct {
	buf     bytes.Buffer
	cap     int64
	written int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.cap - w.written
	if remaining <= 0 {
		return len(p), nil // discard; claim success to avoid broken-pipe
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := w.buf.Write(p)
	w.written += int64(n)
	return len(p), err // always claim full consumption
}

// Result captures everything a caller could want about a subprocess
// invocation. The shape matches (rc, stdout, stderr) from the Python
// reference, plus a TimedOut flag so callers don't have to string-match
// on errors.
type Result struct {
	// ExitCode is the process exit code. -1 when the process failed
	// to start (e.g. binary not found) or was killed by a signal.
	ExitCode int
	// Stdout captures everything the child wrote to fd 1.
	Stdout string
	// Stderr captures everything the child wrote to fd 2.
	Stderr string
	// TimedOut is true when the process was killed because its
	// context deadline expired.
	TimedOut bool
	// Err is the underlying error from os/exec, if any. Callers
	// usually only care about TimedOut and ExitCode — Err is
	// retained for logging and for tests that need the raw error.
	Err error
}

// Success reports whether the process exited cleanly (exit 0, no
// timeout). It does NOT guarantee Stderr is empty — many Unix tools
// log informational output to stderr while still exiting 0.
func (r Result) Success() bool {
	return r.Err == nil && r.ExitCode == 0 && !r.TimedOut
}

// Run executes name with args under DefaultTimeout. It is the
// 90%-case helper. For anything that needs a custom timeout, stdin,
// or a caller-supplied context, use RunCtx.
func Run(name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	return RunCtx(ctx, nil, name, args...)
}

// RunCtx executes name with args using ctx for cancellation. If stdin
// is non-nil its contents are piped to the child's stdin. The caller
// controls the timeout via the context — this mirrors the pattern
// used by os/exec.CommandContext throughout the stdlib.
//
// On context cancellation (including deadline exceeded) the child is
// killed and Result.TimedOut is set. That lets callers branch on
// "real failure" vs "we gave up waiting" without string-matching
// error messages.
func RunCtx(ctx context.Context, stdin io.Reader, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr limitedWriter
	stdout.cap = maxExecOutputBytes
	stderr.cap = maxExecOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != nil {
		cmd.Stdin = stdin
	}

	err := cmd.Run()

	res := Result{
		Stdout: stdout.buf.String(),
		Stderr: stderr.buf.String(),
		Err:    err,
	}

	// Deadline-exceeded detection. We check the context rather than
	// type-asserting on err because the error surface for killed
	// children varies between platforms (ExitError vs *os.SyscallError).
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
	}

	// ExitCode normalization. cmd.ProcessState is nil when the
	// process never started (e.g. binary missing) — signal that
	// with -1 rather than panicking on a nil deref.
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		res.ExitCode = -1
	}

	return res
}
