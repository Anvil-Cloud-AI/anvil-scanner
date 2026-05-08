package exec

import (
	"testing"
)

// ── limitedWriter unit tests ──────────────────────────────────────────────────

// TestLimitedWriter_ExactCap verifies that writing exactly cap bytes stores all
// of them and reports the full length consumed.
func TestLimitedWriter_ExactCap(t *testing.T) {
	w := &limitedWriter{cap: 10}
	data := []byte("0123456789") // exactly 10 bytes

	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() returned n=%d, want %d", n, len(data))
	}
	if w.buf.Len() != 10 {
		t.Errorf("buf.Len()=%d, want 10", w.buf.Len())
	}
	if got := w.buf.String(); got != "0123456789" {
		t.Errorf("buf content = %q, want %q", got, "0123456789")
	}
}

// TestLimitedWriter_OverCap verifies that bytes beyond the cap are silently
// discarded. The implementation reslices p to remaining before calling
// buf.Write, so the returned n equals the bytes actually stored (not the
// original len(p)). The zero-cap fast-path (remaining <= 0) does return
// len(p) to claim full consumption; this test covers the partial-fit path.
func TestLimitedWriter_OverCap(t *testing.T) {
	w := &limitedWriter{cap: 5}
	data := []byte("ABCDEFGHIJ") // 10 bytes, only first 5 fit

	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	// The implementation reslices p to remaining (5) then returns len(p)
	// where p is now the 5-byte slice — so n == 5.
	if n != 5 {
		t.Errorf("Write() returned n=%d, want 5 (remaining bytes stored)", n)
	}
	// Only the first 5 bytes are actually stored.
	if w.buf.Len() != 5 {
		t.Errorf("buf.Len()=%d, want 5", w.buf.Len())
	}
	if got := w.buf.String(); got != "ABCDE" {
		t.Errorf("buf content = %q, want %q", got, "ABCDE")
	}
	// written counter must reflect the 5 stored bytes.
	if w.written != 5 {
		t.Errorf("written=%d, want 5", w.written)
	}
}

// TestLimitedWriter_MultipleWritesExceedCap verifies that multiple sequential
// writes that collectively exceed the cap store only up to cap bytes in total.
func TestLimitedWriter_MultipleWritesExceedCap(t *testing.T) {
	w := &limitedWriter{cap: 8}

	// First write: 5 bytes — fits entirely within cap.
	n1, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("first Write() error: %v", err)
	}
	if n1 != 5 {
		t.Errorf("first Write() n=%d, want 5", n1)
	}

	// Second write: 6 bytes — only 3 fit (8 - 5 = 3 remaining).
	// p is resliced to 3 before buf.Write; returned n == 3.
	n2, err := w.Write([]byte(" world"))
	if err != nil {
		t.Fatalf("second Write() error: %v", err)
	}
	if n2 != 3 {
		t.Errorf("second Write() n=%d, want 3 (only 3 bytes remain in cap)", n2)
	}

	// Third write: cap fully exhausted — fast-path returns len(p) == 8.
	n3, err := w.Write([]byte("overflow"))
	if err != nil {
		t.Fatalf("third Write() error: %v", err)
	}
	if n3 != 8 {
		t.Errorf("third Write() n=%d, want 8 (fast-path claims full len(p))", n3)
	}

	// Exactly 8 bytes stored total.
	if w.buf.Len() != 8 {
		t.Errorf("buf.Len()=%d, want 8", w.buf.Len())
	}
	if got := w.buf.String(); got != "hello wo" {
		t.Errorf("buf content = %q, want %q", got, "hello wo")
	}
}

// TestLimitedWriter_ZeroCap verifies that a zero-cap writer discards every
// byte written to it while still claiming full consumption.
func TestLimitedWriter_ZeroCap(t *testing.T) {
	w := &limitedWriter{cap: 0}

	n, err := w.Write([]byte("anything"))
	if err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	if n != 8 {
		t.Errorf("Write() n=%d, want 8 (must claim full len(p))", n)
	}
	if w.buf.Len() != 0 {
		t.Errorf("buf.Len()=%d, want 0 for zero-cap writer", w.buf.Len())
	}
}
