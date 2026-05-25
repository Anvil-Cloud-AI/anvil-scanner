//go:build darwin || linux

// Package hardening applies auto-fixable remediation for failing scan checks.
// Every modified file is snapshotted via the backup.Manager before any change
// is made.  If sshd_config validation fails after a patch, the temp file is
// removed and the original is left untouched.
package hardening

import (
	"runtime"

	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/backup"
	"github.com/Anvil-Cloud-AI/anvil-scanner/internal/scan"
)

// Action records what happened to one check during a hardening run.
type Action struct {
	CheckID string
	Name    string
	Detail  string // what was applied, why it was skipped, or the error
}

// Result summarises a hardening run.
type Result struct {
	Applied []Action // fixes that were successfully applied
	Skipped []Action // checks that passed, were already correct, or can't be auto-fixed
	Failed  []Action // fixes that were attempted but errored
}

// Apply examines the provided scan checks and applies all auto-fixable
// hardening actions.  bkup must be a freshly created Manager; files are
// snapshotted before modification.  platform is scan.Platform() ("Linux",
// "Darwin", etc.).
func Apply(checks []scan.Check, bkup *backup.Manager, platform string, isRPi bool) Result {
	var r Result
	idx := indexChecks(checks)

	applySSH(idx, bkup, platform, &r)

	switch runtime.GOOS {
	case "linux":
		applyLinuxFirewall(idx, &r)
	case "darwin":
		applyMacOSFirewall(idx, &r)
	}

	if isRPi {
		applyRPi(idx, bkup, &r)
	}

	return r
}

// indexChecks builds a checkID → Status map for O(1) lookup.
func indexChecks(checks []scan.Check) map[string]scan.Status {
	m := make(map[string]scan.Status, len(checks))
	for _, c := range checks {
		m[string(c.ID)] = c.Status
	}
	return m
}

// needsFix reports whether id has status FAIL or WARN in idx.
func needsFix(idx map[string]scan.Status, id string) bool {
	s, ok := idx[id]
	return ok && (s == scan.StatusFail || s == scan.StatusWarn)
}

func (r *Result) applied(id, name, detail string) {
	r.Applied = append(r.Applied, Action{CheckID: id, Name: name, Detail: detail})
}

func (r *Result) skipped(id, name, detail string) {
	r.Skipped = append(r.Skipped, Action{CheckID: id, Name: name, Detail: detail})
}

func (r *Result) failed(id, name, detail string) {
	r.Failed = append(r.Failed, Action{CheckID: id, Name: name, Detail: detail})
}
