//go:build windows

package scan

import iexec "github.com/Anvil-Cloud-AI/anvil-scanner/internal/exec"

// DetectWindowsSKU reads the Windows InstallationType from the registry to
// distinguish Windows 11 (Client) from Windows Server. It shells out to reg.exe
// via the shared exec helper (no new dependency). Returns SKUUnknown when the
// value cannot be read.
func DetectWindowsSKU() WindowsSKU {
	r := iexec.Run("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "InstallationType")
	if !r.Success() {
		return SKUUnknown
	}
	return parseInstallationType(r.Stdout)
}
