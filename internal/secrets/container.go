//go:build darwin || linux

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	containerMagic          = "ANVILSEC\n"
	containerVersion        = "1\n"
	containerCurrentVersion = 1
	headerSizeMax           = 4096
	saltSizeMax             = 1024
	scryptN                 = 1 << 17 // 131072 — OWASP minimum for key-wrapping
	scryptR                 = 8
	scryptP                 = 1
	scryptKeyLen            = 32
	scryptSaltLen           = 16
	scryptNMin              = 1 << 14 // allow containers created with N=16384 to still load
	scryptNMax              = 1 << 20
	scryptRMax              = 64
	scryptPMax              = 3
	minPassphraseLen        = 12
	nonceLen                = 12 // AES-GCM standard
	cipherAES256GCM         = "aes256gcm"
	kdfKeyring              = "keyring"
	kdfScrypt               = "scrypt"
	kdfFile                 = "file"
)

// containerHeader is the JSON metadata block that appears between the
// version line and the raw ciphertext in a secrets container file.
// Fields follow ADR-0002 exactly; omitempty keeps the header compact
// when kdf != "scrypt".
type containerHeader struct {
	KDF     string `json:"kdf"`
	Cipher  string `json:"cipher,omitempty"`
	Salt    string `json:"salt,omitempty"`
	N       int    `json:"n,omitempty"`
	R       int    `json:"r,omitempty"`
	P       int    `json:"p,omitempty"`
	Created string `json:"created"`
}

// packContainer serialises a container as:
//
//	ANVILSEC\n  1\n  <JSON header>\n  <ciphertext>
func packContainer(h containerHeader, ciphertext []byte) ([]byte, error) {
	hdrJSON, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("secrets: marshal header: %w", err)
	}

	var buf []byte
	buf = append(buf, containerMagic...)
	buf = append(buf, containerVersion...)
	buf = append(buf, hdrJSON...)
	buf = append(buf, '\n')
	buf = append(buf, ciphertext...)
	return buf, nil
}

// unpackContainer parses a container blob produced by packContainer.
//
// Return semantics (see ADR-0002):
//   - legacy=true, hdr=nil  → magic present but cipher absent or "fernet";
//     caller must print the migration hint.
//   - legacy=false, hdr non-nil → valid Go container, ready to decrypt.
//   - hdr=nil, legacy=false → blob does not start with magic; caller treats
//     as an error.
func unpackContainer(blob []byte) (hdr *containerHeader, ciphertext []byte, legacy bool, err error) {
	// ── magic check ──────────────────────────────────────────────────────
	if !strings.HasPrefix(string(blob), containerMagic) {
		return nil, nil, false, errors.New("secrets: not a valid container (missing magic)")
	}
	rest := blob[len(containerMagic):]

	// ── version line ─────────────────────────────────────────────────────
	nlIdx := strings.IndexByte(string(rest), '\n')
	if nlIdx < 0 {
		return nil, nil, false, errors.New("secrets: container missing version line")
	}
	// We accept version "1" only; future versions require a new ADR.
	versionLine := string(rest[:nlIdx])
	if versionLine != "1" {
		return nil, nil, false, fmt.Errorf("secrets: unsupported container version %q", versionLine)
	}
	rest = rest[nlIdx+1:]

	// ── header JSON ───────────────────────────────────────────────────────
	// Locate the newline that terminates the JSON header, but cap the
	// search at headerSizeMax to prevent header-bloat DoS.
	searchLen := len(rest)
	if searchLen > headerSizeMax {
		searchLen = headerSizeMax
	}
	hdrEnd := strings.IndexByte(string(rest[:searchLen]), '\n')
	if hdrEnd < 0 {
		if len(rest) > headerSizeMax {
			return nil, nil, false, fmt.Errorf("secrets: header exceeds %d-byte limit", headerSizeMax)
		}
		return nil, nil, false, errors.New("secrets: container header not terminated")
	}

	hdrBytes := rest[:hdrEnd]
	ciphertext = rest[hdrEnd+1:]

	var h containerHeader
	if err := json.Unmarshal(hdrBytes, &h); err != nil {
		return nil, nil, false, fmt.Errorf("secrets: malformed header JSON: %w", err)
	}

	// ── legacy Fernet detection ───────────────────────────────────────────
	// A container with cipher absent or != "aes256gcm" came from the Python
	// implementation; we cannot decrypt it — return legacy=true so the
	// caller can print the migration hint.
	if h.Cipher != cipherAES256GCM {
		return nil, nil, true, nil
	}

	// ── kdf validation ────────────────────────────────────────────────────
	switch h.KDF {
	case kdfKeyring, kdfScrypt, kdfFile:
		// valid
	default:
		return nil, nil, false, fmt.Errorf("secrets: unknown kdf %q", h.KDF)
	}

	// ── scrypt-specific validation ────────────────────────────────────────
	if h.KDF == kdfScrypt {
		if err := validateScryptParams(h.N, h.R, h.P); err != nil {
			return nil, nil, false, err
		}
		if h.Salt == "" {
			return nil, nil, false, errors.New("secrets: scrypt container missing salt")
		}
		if len(h.Salt) > saltSizeMax {
			return nil, nil, false, fmt.Errorf("secrets: salt field exceeds %d-byte limit", saltSizeMax)
		}
	}

	return &h, ciphertext, false, nil
}

// validateScryptParams guards against malicious or corrupted headers that
// would cause OOM by specifying extreme N values.  Exported so tests can
// exercise it directly.
func validateScryptParams(n, r, p int) error {
	if n < scryptNMin || n > scryptNMax {
		return fmt.Errorf("secrets: scrypt N %d out of allowed range [%d, %d]", n, scryptNMin, scryptNMax)
	}
	// N must be a power of two.
	if n&(n-1) != 0 {
		return fmt.Errorf("secrets: scrypt N %d is not a power of 2", n)
	}
	if r < 1 || r > scryptRMax {
		return fmt.Errorf("secrets: scrypt r %d out of allowed range [1, %d]", r, scryptRMax)
	}
	if p < 1 || p > scryptPMax {
		return fmt.Errorf("secrets: scrypt p %d out of allowed range [1, %d]", p, scryptPMax)
	}
	return nil
}

// encryptAES256GCM encrypts plaintext with a 256-bit key using AES-GCM.
// The returned blob is: nonce (12 bytes) || GCM_ciphertext || GCM_tag.
func encryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: GCM init: %w", err)
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secrets: nonce generation: %w", err)
	}

	// Seal appends ciphertext+tag to nonce, producing nonce||ct||tag.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAES256GCM decrypts a blob produced by encryptAES256GCM.
func decryptAES256GCM(key, data []byte) ([]byte, error) {
	if len(data) < nonceLen {
		return nil, errors.New("secrets: ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: GCM init: %w", err)
	}

	nonce := data[:nonceLen]
	ciphertextAndTag := data[nonceLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: AES-GCM decrypt: %w", err)
	}
	return plaintext, nil
}

// deriveKeyScrypt derives a 32-byte AES key from passphrase and salt using
// the scrypt KDF with the given parameters.  The returned bytes are used
// directly as an AES-256 key (not base64-encoded).
func deriveKeyScrypt(passphrase string, salt []byte, n, r, p int) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("secrets: passphrase must not be empty")
	}
	if len(salt) < 8 {
		return nil, fmt.Errorf("secrets: salt too short (%d bytes, minimum 8)", len(salt))
	}
	if err := validateScryptParams(n, r, p); err != nil {
		return nil, err
	}

	// golang.org/x/crypto/scrypt does not accept a maxmem parameter; enforcement is via scryptN/scryptR/scryptP bounds checks above.
	key, err := scrypt.Key([]byte(passphrase), salt, n, r, p, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("secrets: scrypt KDF: %w", err)
	}
	return key, nil
}
