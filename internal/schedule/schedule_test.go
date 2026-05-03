//go:build darwin || linux

package schedule

import (
	"strings"
	"testing"
)

func TestBuildPlist_EscapesXML(t *testing.T) {
	content, err := buildPlist("/usr/local/bin/anvil-scanner")
	if err != nil {
		t.Fatalf("buildPlist: %v", err)
	}
	if !strings.Contains(content, "<string>com.anvil-scanner.scan</string>") {
		t.Error("plist missing Label")
	}
	if !strings.Contains(content, "/usr/local/bin/anvil-scanner") {
		t.Error("plist missing binary path")
	}
	if !strings.Contains(content, "<integer>3600</integer>") {
		t.Error("plist missing StartInterval")
	}
	if !strings.Contains(content, "<false/>") {
		t.Error("plist missing RunAtLoad false")
	}
}

func TestBuildPlist_XMLEscapesSpecialChars(t *testing.T) {
	content, err := buildPlist("/home/user/bin/a&b<c>d")
	if err != nil {
		t.Fatalf("buildPlist: %v", err)
	}
	// Should be escaped
	if strings.Contains(content, "/home/user/bin/a&b<c>d") {
		t.Error("path was not XML-escaped")
	}
	if !strings.Contains(content, "a&amp;b&lt;c&gt;d") {
		t.Error("expected XML-escaped path in plist")
	}
}

func TestCronEntry_Format(t *testing.T) {
	entry, err := cronEntry("/usr/local/bin/anvil-scanner")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(entry, "0 * * * *") {
		t.Errorf("expected hourly cron schedule, got: %s", entry)
	}
	if !strings.Contains(entry, "/usr/local/bin/anvil-scanner") {
		t.Errorf("expected binary path in entry: %s", entry)
	}
	if !strings.Contains(entry, cronComment) {
		t.Errorf("expected comment %q in entry: %s", cronComment, entry)
	}
	if !strings.Contains(entry, "--no-ai") {
		t.Errorf("expected --no-ai flag in entry: %s", entry)
	}
}

func TestCronEntry_RejectsUnsafePath(t *testing.T) {
	for _, bad := range []string{`/usr/"bin/anvil`, `/usr/\bin/anvil`} {
		_, err := cronEntry(bad)
		if err == nil {
			t.Errorf("expected error for unsafe path %q", bad)
		}
	}
}

func TestFilterCron_RemovesAnvilLines(t *testing.T) {
	lines := []string{
		"0 * * * * /usr/bin/backup  # some other job",
		"0 * * * * /usr/local/bin/anvil-scanner --no-ai  # anvil-scanner",
		"30 2 * * * /usr/bin/cleanup",
	}
	filtered := filterCron(lines)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 lines after filter, got %d", len(filtered))
	}
	for _, l := range filtered {
		if strings.Contains(l, cronComment) {
			t.Errorf("filterCron left anvil-scanner entry: %s", l)
		}
	}
}

func TestFilterCron_NoChange_WhenNonePresent(t *testing.T) {
	lines := []string{
		"0 * * * * /usr/bin/backup",
		"30 2 * * * /usr/bin/cleanup",
	}
	filtered := filterCron(lines)
	if len(filtered) != len(lines) {
		t.Errorf("expected no change, got %d lines", len(filtered))
	}
}
