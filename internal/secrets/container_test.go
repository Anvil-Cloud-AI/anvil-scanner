//go:build darwin || linux

package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, scryptKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random key: %v", err)
	}
	return key
}

func randomSalt(t *testing.T) []byte {
	t.Helper()
	salt := make([]byte, scryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("random salt: %v", err)
	}
	return salt
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ── packContainer / unpackContainer round-trips ───────────────────────────────

func TestPackUnpack_Keyring(t *testing.T) {
	h := containerHeader{
		KDF:     kdfKeyring,
		Cipher:  cipherAES256GCM,
		Created: nowRFC3339(),
	}
	ct := []byte("fake ciphertext bytes")

	blob, err := packContainer(h, ct)
	if err != nil {
		t.Fatalf("packContainer: %v", err)
	}

	got, gotCT, legacy, err := unpackContainer(blob)
	if err != nil {
		t.Fatalf("unpackContainer: %v", err)
	}
	if legacy {
		t.Fatal("expected legacy=false for keyring container")
	}
	if got == nil {
		t.Fatal("expected non-nil header")
	}
	if got.KDF != kdfKeyring {
		t.Errorf("KDF: got %q, want %q", got.KDF, kdfKeyring)
	}
	if got.Cipher != cipherAES256GCM {
		t.Errorf("Cipher: got %q, want %q", got.Cipher, cipherAES256GCM)
	}
	if string(gotCT) != string(ct) {
		t.Errorf("ciphertext: got %q, want %q", gotCT, ct)
	}
}

func TestPackUnpack_Scrypt(t *testing.T) {
	salt := randomSalt(t)
	h := containerHeader{
		KDF:     kdfScrypt,
		Cipher:  cipherAES256GCM,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		N:       scryptN,
		R:       scryptR,
		P:       scryptP,
		Created: nowRFC3339(),
	}
	ct := []byte("scrypt encrypted data")

	blob, err := packContainer(h, ct)
	if err != nil {
		t.Fatalf("packContainer: %v", err)
	}

	got, gotCT, legacy, err := unpackContainer(blob)
	if err != nil {
		t.Fatalf("unpackContainer: %v", err)
	}
	if legacy {
		t.Fatal("expected legacy=false")
	}
	if got.KDF != kdfScrypt {
		t.Errorf("KDF: got %q want %q", got.KDF, kdfScrypt)
	}
	if got.N != scryptN || got.R != scryptR || got.P != scryptP {
		t.Errorf("scrypt params: got N=%d r=%d p=%d, want N=%d r=%d p=%d",
			got.N, got.R, got.P, scryptN, scryptR, scryptP)
	}
	if string(gotCT) != string(ct) {
		t.Errorf("ciphertext mismatch")
	}
}

func TestPackUnpack_File(t *testing.T) {
	h := containerHeader{
		KDF:     kdfFile,
		Cipher:  cipherAES256GCM,
		Created: nowRFC3339(),
	}
	ct := []byte("file backend data")

	blob, err := packContainer(h, ct)
	if err != nil {
		t.Fatalf("packContainer: %v", err)
	}

	got, _, legacy, err := unpackContainer(blob)
	if err != nil {
		t.Fatalf("unpackContainer: %v", err)
	}
	if legacy {
		t.Fatal("expected legacy=false")
	}
	if got.KDF != kdfFile {
		t.Errorf("KDF: got %q want %q", got.KDF, kdfFile)
	}
}

// ── Legacy detection ──────────────────────────────────────────────────────────

func TestUnpack_LegacyNoCipher(t *testing.T) {
	// Simulate a Python Fernet container: magic + version + header with no cipher field.
	h := containerHeader{
		KDF:     kdfKeyring,
		Created: nowRFC3339(),
		// Cipher intentionally omitted → legacy
	}
	blob, err := packContainer(h, []byte("fernet blob"))
	if err != nil {
		t.Fatalf("packContainer: %v", err)
	}

	got, gotCT, legacy, err := unpackContainer(blob)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !legacy {
		t.Fatal("expected legacy=true for header missing cipher field")
	}
	if got != nil {
		t.Errorf("expected nil hdr for legacy container, got %+v", got)
	}
	if gotCT != nil {
		t.Errorf("expected nil ciphertext for legacy container")
	}
}

func TestUnpack_LegacyFernetCipher(t *testing.T) {
	// Simulate a container with cipher:"fernet" explicitly set.
	raw := containerMagic + containerVersion +
		`{"kdf":"keyring","cipher":"fernet","created":"2026-01-01T00:00:00Z"}` + "\n" +
		"payload"

	got, gotCT, legacy, err := unpackContainer([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !legacy {
		t.Fatal("expected legacy=true for cipher=fernet")
	}
	if got != nil || gotCT != nil {
		t.Error("expected nil hdr and ciphertext for legacy container")
	}
}

// ── Error cases ───────────────────────────────────────────────────────────────

func TestUnpack_BadMagic(t *testing.T) {
	_, _, legacy, err := unpackContainer([]byte("NOTMAGIC\n1\n{}\ndata"))
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
	if legacy {
		t.Fatal("expected legacy=false when magic is wrong")
	}
}

func TestUnpack_MissingVersionLine(t *testing.T) {
	blob := []byte(containerMagic) // nothing after magic
	_, _, _, err := unpackContainer(blob)
	if err == nil {
		t.Fatal("expected error for missing version line")
	}
}

func TestUnpack_UnsupportedVersion(t *testing.T) {
	raw := containerMagic + "2\n" + `{"kdf":"keyring","cipher":"aes256gcm","created":"2026-01-01T00:00:00Z"}` + "\ndata"
	_, _, _, err := unpackContainer([]byte(raw))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestUnpack_MalformedHeaderJSON(t *testing.T) {
	raw := containerMagic + containerVersion + "not-json\ndata"
	_, _, _, err := unpackContainer([]byte(raw))
	if err == nil {
		t.Fatal("expected error for malformed header JSON")
	}
}

func TestUnpack_OversizedHeader(t *testing.T) {
	// Build a header line that exceeds headerSizeMax bytes.
	bigHeader := strings.Repeat("x", headerSizeMax+1)
	raw := containerMagic + containerVersion + bigHeader + "\ndata"
	_, _, _, err := unpackContainer([]byte(raw))
	if err == nil {
		t.Fatal("expected error for oversized header")
	}
}

func TestUnpack_UnknownKDF(t *testing.T) {
	raw := containerMagic + containerVersion +
		`{"kdf":"argon2id","cipher":"aes256gcm","created":"2026-01-01T00:00:00Z"}` + "\ndata"
	_, _, _, err := unpackContainer([]byte(raw))
	if err == nil {
		t.Fatal("expected error for unknown kdf")
	}
}

func TestUnpack_ScryptMissingSalt(t *testing.T) {
	raw := containerMagic + containerVersion +
		`{"kdf":"scrypt","cipher":"aes256gcm","n":32768,"r":8,"p":1,"created":"2026-01-01T00:00:00Z"}` + "\ndata"
	_, _, _, err := unpackContainer([]byte(raw))
	if err == nil {
		t.Fatal("expected error for scrypt container missing salt")
	}
}

// ── validateScryptParams ──────────────────────────────────────────────────────

func TestValidateScryptParams_Valid(t *testing.T) {
	cases := []struct{ n, r, p int }{
		{scryptNMin, 1, 1},
		{scryptN, scryptR, scryptP},
		{scryptNMax, scryptRMax, scryptPMax},
		{1 << 16, 4, 2},
	}
	for _, c := range cases {
		if err := validateScryptParams(c.n, c.r, c.p); err != nil {
			t.Errorf("validateScryptParams(%d,%d,%d): unexpected error: %v", c.n, c.r, c.p, err)
		}
	}
}

func TestValidateScryptParams_NonPowerOfTwo(t *testing.T) {
	cases := []int{32769, 32767, 1<<14 + 1, 0}
	for _, n := range cases {
		// Only test values in range first; out-of-range N will be caught by range check.
		// Pick n values that are in range but not powers of two.
		if n < scryptNMin || n > scryptNMax {
			continue
		}
		if err := validateScryptParams(n, 8, 1); err == nil {
			t.Errorf("validateScryptParams(N=%d): expected error for non-power-of-2", n)
		}
	}
}

func TestValidateScryptParams_NTooSmall(t *testing.T) {
	if err := validateScryptParams(scryptNMin/2, 8, 1); err == nil {
		t.Error("expected error for N below minimum")
	}
}

func TestValidateScryptParams_NTooLarge(t *testing.T) {
	if err := validateScryptParams(scryptNMax*2, 8, 1); err == nil {
		t.Error("expected error for N above maximum")
	}
}

func TestValidateScryptParams_ROutOfRange(t *testing.T) {
	if err := validateScryptParams(scryptN, 0, 1); err == nil {
		t.Error("expected error for r=0")
	}
	if err := validateScryptParams(scryptN, scryptRMax+1, 1); err == nil {
		t.Errorf("expected error for r=%d", scryptRMax+1)
	}
}

func TestValidateScryptParams_POutOfRange(t *testing.T) {
	if err := validateScryptParams(scryptN, 8, 0); err == nil {
		t.Error("expected error for p=0")
	}
	if err := validateScryptParams(scryptN, 8, scryptPMax+1); err == nil {
		t.Errorf("expected error for p=%d", scryptPMax+1)
	}
}

// ── encryptAES256GCM / decryptAES256GCM round-trip ───────────────────────────

func TestEncryptDecryptAES256GCM_RoundTrip(t *testing.T) {
	key := randomKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ct, err := encryptAES256GCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) < nonceLen {
		t.Fatalf("ciphertext too short: %d bytes", len(ct))
	}

	pt, err := decryptAES256GCM(key, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestEncryptDecryptAES256GCM_WrongKey(t *testing.T) {
	key := randomKey(t)
	ct, err := encryptAES256GCM(key, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongKey := randomKey(t)
	_, err = decryptAES256GCM(wrongKey, ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestEncryptDecryptAES256GCM_Tampered(t *testing.T) {
	key := randomKey(t)
	ct, err := encryptAES256GCM(key, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip the last byte (in the GCM tag).
	ct[len(ct)-1] ^= 0xFF
	_, err = decryptAES256GCM(key, ct)
	if err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext")
	}
}

func TestDecryptAES256GCM_TooShort(t *testing.T) {
	key := randomKey(t)
	_, err := decryptAES256GCM(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
}

// ── deriveKeyScrypt ───────────────────────────────────────────────────────────

func TestDeriveKeyScrypt_Output(t *testing.T) {
	salt := randomSalt(t)
	key, err := deriveKeyScrypt("correcthorsebatterystaple", salt, scryptN, scryptR, scryptP)
	if err != nil {
		t.Fatalf("deriveKeyScrypt: %v", err)
	}
	if len(key) != scryptKeyLen {
		t.Errorf("key length: got %d, want %d", len(key), scryptKeyLen)
	}
}

func TestDeriveKeyScrypt_Deterministic(t *testing.T) {
	salt := randomSalt(t)
	passphrase := "correcthorsebatterystaple"

	key1, err := deriveKeyScrypt(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	key2, err := deriveKeyScrypt(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("KDF is not deterministic")
	}
}

func TestDeriveKeyScrypt_DifferentSalts(t *testing.T) {
	salt1 := randomSalt(t)
	salt2 := randomSalt(t)
	passphrase := "correcthorsebatterystaple"

	key1, _ := deriveKeyScrypt(passphrase, salt1, scryptN, scryptR, scryptP)
	key2, _ := deriveKeyScrypt(passphrase, salt2, scryptN, scryptR, scryptP)
	if string(key1) == string(key2) {
		t.Error("different salts produced identical keys")
	}
}

func TestDeriveKeyScrypt_EmptyPassphrase(t *testing.T) {
	salt := randomSalt(t)
	_, err := deriveKeyScrypt("", salt, scryptN, scryptR, scryptP)
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestDeriveKeyScrypt_ShortSalt(t *testing.T) {
	_, err := deriveKeyScrypt("correcthorsebatterystaple", []byte("short"), scryptN, scryptR, scryptP)
	if err == nil {
		t.Fatal("expected error for salt shorter than 8 bytes")
	}
}

func TestDeriveKeyScrypt_BadParams(t *testing.T) {
	salt := randomSalt(t)
	_, err := deriveKeyScrypt("correcthorsebatterystaple", salt, 3, scryptR, scryptP) // N not power-of-2 and out of range
	if err == nil {
		t.Fatal("expected error for invalid scrypt params")
	}
}

// ── Full container round-trip (encrypt + pack + unpack + decrypt) ─────────────

func TestFullContainerRoundTrip_Scrypt(t *testing.T) {
	salt := randomSalt(t)
	passphrase := "correcthorsebatterystaple"

	key, err := deriveKeyScrypt(passphrase, salt, scryptN, scryptR, scryptP)
	if err != nil {
		t.Fatalf("deriveKeyScrypt: %v", err)
	}

	plaintext := []byte(`{"CLAUDE_KEY":"sk-test","OPENAI_KEY":"openai-test"}`)
	ct, err := encryptAES256GCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	h := containerHeader{
		KDF:     kdfScrypt,
		Cipher:  cipherAES256GCM,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		N:       scryptN,
		R:       scryptR,
		P:       scryptP,
		Created: nowRFC3339(),
	}

	blob, err := packContainer(h, ct)
	if err != nil {
		t.Fatalf("packContainer: %v", err)
	}

	gotHdr, gotCT, legacy, err := unpackContainer(blob)
	if err != nil {
		t.Fatalf("unpackContainer: %v", err)
	}
	if legacy {
		t.Fatal("expected legacy=false")
	}

	saltBytes, err := base64.StdEncoding.DecodeString(gotHdr.Salt)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}

	key2, err := deriveKeyScrypt(passphrase, saltBytes, gotHdr.N, gotHdr.R, gotHdr.P)
	if err != nil {
		t.Fatalf("re-derive key: %v", err)
	}

	pt, err := decryptAES256GCM(key2, gotCT)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q want %q", pt, plaintext)
	}
}
