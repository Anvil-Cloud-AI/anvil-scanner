//go:build windows

package scan

import "os"

// fileOwnerUID is a Tier-0 Windows placeholder. File ownership on Windows is
// expressed via SIDs rather than POSIX UIDs, so there is no meaningful uint32
// owner to return here. It always reports 0 until real Windows ownership
// checks are implemented in a later phase.
func fileOwnerUID(_ os.FileInfo) uint32 {
	return 0
}
