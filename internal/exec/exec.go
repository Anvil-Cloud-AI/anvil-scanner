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
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// RunElevated runs name with args, prefixing with "sudo" when the current
// process is not already root.  It prints a one-line notice to stderr so the
// user knows why a sudo password prompt may appear.
func RunElevated(name string, args ...string) Result {
	if os.Getuid() == 0 {
		return Run(name, args...)
	}
	fmt.Fprintf(os.Stderr, "[sudo] %s %s\n", name, strings.Join(args, " "))
	all := append([]string{name}, args...)
	return Run("sudo", all...)
}

// ReadFileElevated reads path, retrying with sudo when the initial read fails
// with permission denied.
func ReadFileElevated(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, nil
	}
	if !os.IsPermission(err) {
		return nil, err
	}
	r := RunElevated("cat", path)
	if !r.Success() {
		return nil, fmt.Errorf("exec: sudo read %s (exit %d): %s", path, r.ExitCode, r.Stderr)
	}
	return []byte(r.Stdout), nil
}

// ChmodElevated changes the mode of path, using sudo when not root.
func ChmodElevated(path, mode string) error {
	r := RunElevated("chmod", mode, path)
	if !r.Success() {
		return fmt.Errorf("exec: chmod %s %s (exit %d): %s", mode, path, r.ExitCode, r.Stderr)
	}
	return nil
}

// WriteFileElevated writes data to path with the given octal mode string
// (e.g. "0600").  It stages through a temp file in /tmp so that the sudo mv
// is a simple rename, not a full copy through the kernel.
func WriteFileElevated(path string, data []byte, mode string) error {
	// Stage to a temp file we own.
	tmp, err := os.CreateTemp("", "anvil-elevated-*")
	if err != nil {
		return fmt.Errorf("exec: create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // best-effort cleanup on failure

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("exec: write temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("exec: close temp for %s: %w", path, err)
	}

	// We own the temp file, so use os.Chmod directly — no sudo needed.
	octal, parseErr := strconv.ParseUint(mode, 8, 32)
	if parseErr != nil {
		return fmt.Errorf("exec: invalid mode %q: %w", mode, parseErr)
	}
	if err := os.Chmod(tmpPath, os.FileMode(octal)); err != nil {
		return fmt.Errorf("exec: chmod temp for %s: %w", path, err)
	}

	r := RunElevated("mv", tmpPath, path)
	if !r.Success() {
		return fmt.Errorf("exec: sudo mv to %s (exit %d): %s", path, r.ExitCode, r.Stderr)
	}
	return nil
}

// WarmSudoCredentials runs "sudo -v" with stdin/stdout/stderr connected to
// the real terminal so the user can enter their password once before a series
// of elevated operations.  On systems with NOPASSWD this is a no-op.
// Returns an error if sudo credentials cannot be obtained.
func WarmSudoCredentials() error {
	if os.Getuid() == 0 {
		return nil // already root
	}
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
