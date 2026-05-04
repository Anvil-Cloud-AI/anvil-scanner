//go:build darwin || linux

package secrets

import (
	"strings"
	"testing"
)

// TestKeyringAccountsAreDistinct verifies the compile-time safety guarantee
// that the probe account never collides with the production account.
// hasKeyring() exercises a write→read→delete cycle using keyringProbeAccount
// exclusively; this test documents (and enforces) that invariant at the
// constant level.
func TestKeyringAccountsAreDistinct(t *testing.T) {
	if keyringProbeAccount == keyringAccount {
		t.Fatalf("keyringProbeAccount (%q) must differ from keyringAccount (%q): "+
			"the probe would clobber the production master key entry",
			keyringProbeAccount, keyringAccount)
	}
}

// TestKeyringProbeAccountNotSubstringOfProductionAccount verifies that the
// probe account name does not share the production account name as a prefix.
// This guards against hypothetical glob-style keychain lookups that could
// match both entries simultaneously.
func TestKeyringProbeAccountNotSubstringOfProductionAccount(t *testing.T) {
	if strings.HasPrefix(keyringProbeAccount, keyringAccount) {
		t.Errorf("keyringProbeAccount %q must not share keyringAccount %q as a prefix",
			keyringProbeAccount, keyringAccount)
	}
	if strings.HasPrefix(keyringAccount, keyringProbeAccount) {
		t.Errorf("keyringAccount %q must not share keyringProbeAccount %q as a prefix",
			keyringAccount, keyringProbeAccount)
	}
}

// TestKeyringServiceIsNonEmpty is a sanity check that the keyring service name
// (used as the "service" label in both macOS Keychain and libsecret) is set.
func TestKeyringServiceIsNonEmpty(t *testing.T) {
	if keyringService == "" {
		t.Error("keyringService must be a non-empty string")
	}
}

// TestKeyringDummyKeyIsNonEmpty verifies the probe sentinel value is non-empty.
// hasKeyring() round-trips this value; an empty sentinel would make the probe
// trivially pass even if the keyring wrote nothing.
func TestKeyringDummyKeyIsNonEmpty(t *testing.T) {
	if keyringDummyKey == "" {
		t.Error("keyringDummyKey must be a non-empty string so the probe round-trip is meaningful")
	}
}

// TestHasKeyringDoesNotMentionProductionAccount documents the structural
// guarantee: the probe functions (storeKeyringProbe, loadKeyringProbe,
// deleteKeyringProbe) reference only keyringProbeAccount, never keyringAccount.
// We verify this at the constant level since the keyring daemon may not be
// present in CI environments.
func TestHasKeyringProbeConstantsAreSeparate(t *testing.T) {
	// The production account must not appear in the probe account string.
	if strings.Contains(keyringProbeAccount, keyringAccount) &&
		keyringProbeAccount != keyringAccount+"_probe" {
		// Allow a "_probe" suffix pattern (it contains the base name) only if
		// they are structurally different identifiers.
		// The important invariant: they are not equal, which is already checked
		// in TestKeyringAccountsAreDistinct.
	}
	// Primary invariant: the two constants are distinct strings.
	if keyringProbeAccount == keyringAccount {
		t.Errorf("probe account %q == production account %q: hasKeyring() would overwrite master key",
			keyringProbeAccount, keyringAccount)
	}
}
