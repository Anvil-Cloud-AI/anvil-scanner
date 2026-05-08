//go:build darwin || linux

package secrets

import (
	"bytes"
	"testing"
)

// TestScryptAESGCM_EncryptDecryptRoundTrip verifies that encrypting plaintext
// with a scrypt-derived key and then decrypting it yields the original bytes.
// Uses N=scryptNMin to keep each subtest fast (< 1 s).
func TestScryptAESGCM_EncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		plaintext  []byte
	}{
		{"short plaintext", "correcthorsebatterystaple", []byte("hello")},
		{"empty plaintext", "correcthorsebatterystaple", []byte{}},
		{"json secrets payload", "my-long-secure-passphrase!!", []byte(`{"CLAUDE_KEY":"sk-test","OPENAI_KEY":"sk-openai"}`)},
		{"binary content", "another-long-passphrase123", []byte{0x00, 0xFF, 0xAB, 0xCD, 0x01, 0x02}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			salt := randomSalt(t)

			key, err := deriveKeyScrypt(tc.passphrase, salt, scryptNMin, scryptR, scryptP)
			if err != nil {
				t.Fatalf("deriveKeyScrypt: %v", err)
			}

			ct, err := encryptAES256GCM(key, tc.plaintext)
			if err != nil {
				t.Fatalf("encryptAES256GCM: %v", err)
			}

			pt, err := decryptAES256GCM(key, ct)
			if err != nil {
				t.Fatalf("decryptAES256GCM: %v", err)
			}

			if !bytes.Equal(pt, tc.plaintext) {
				t.Errorf("round-trip mismatch: got %q, want %q", pt, tc.plaintext)
			}
		})
	}
}

// TestScryptAESGCM_WrongPassphraseReturnsError verifies that decrypting with a
// key derived from a different passphrase (same salt) returns an error.
func TestScryptAESGCM_WrongPassphraseReturnsError(t *testing.T) {
	salt := randomSalt(t)
	plaintext := []byte("sensitive secret data")

	correctKey, err := deriveKeyScrypt("correct-passphrase-here", salt, scryptNMin, scryptR, scryptP)
	if err != nil {
		t.Fatalf("derive correct key: %v", err)
	}

	ct, err := encryptAES256GCM(correctKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongKey, err := deriveKeyScrypt("wrong-passphrase-here!!", salt, scryptNMin, scryptR, scryptP)
	if err != nil {
		t.Fatalf("derive wrong key: %v", err)
	}

	_, err = decryptAES256GCM(wrongKey, ct)
	if err == nil {
		t.Fatal("decryptAES256GCM with wrong key returned nil; want error")
	}
}

// TestScryptAESGCM_CorruptCiphertextReturnsError verifies that any corruption
// of the ciphertext blob causes AES-GCM authentication to fail.
func TestScryptAESGCM_CorruptCiphertextReturnsError(t *testing.T) {
	salt := randomSalt(t)
	plaintext := []byte("data to protect")

	key, err := deriveKeyScrypt("long-enough-passphrase!!", salt, scryptNMin, scryptR, scryptP)
	if err != nil {
		t.Fatalf("deriveKeyScrypt: %v", err)
	}

	ct, err := encryptAES256GCM(key, plaintext)
	if err != nil {
		t.Fatalf("encryptAES256GCM: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "flip last byte (GCM tag)",
			mutate: func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[len(c)-1] ^= 0xFF
				return c
			},
		},
		{
			name: "flip first byte (nonce)",
			mutate: func(b []byte) []byte {
				c := make([]byte, len(b))
				copy(c, b)
				c[0] ^= 0x01
				return c
			},
		},
		{
			name: "truncate to nonce only",
			mutate: func(b []byte) []byte {
				return b[:nonceLen]
			},
		},
		{
			name: "completely empty",
			mutate: func(b []byte) []byte {
				return []byte{}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			corrupt := tc.mutate(ct)
			_, err := decryptAES256GCM(key, corrupt)
			if err == nil {
				t.Errorf("decryptAES256GCM with corrupt ciphertext (%s) returned nil; want error",
					tc.name)
			}
		})
	}
}
