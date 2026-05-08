//go:build darwin || linux

package scan

import (
	"os"
	"syscall"
)

// fileOwnerUID returns the UID of the file's owner using the
// Unix-specific Sys() data. The build tag restricts this to
// darwin and linux — the only platforms anvil-scanner supports.
func fileOwnerUID(fi os.FileInfo) uint32 {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return 0
}
