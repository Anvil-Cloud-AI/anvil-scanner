//go:build darwin || linux

package container

import "testing"

func TestParsePS(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   []containerRef
	}{
		{
			name:   "empty output",
			stdout: "",
			want:   nil,
		},
		{
			name:   "two containers",
			stdout: "abc123\tnginx:latest\ndef456\tredis:7",
			want: []containerRef{
				{ID: "abc123", Image: "nginx:latest"},
				{ID: "def456", Image: "redis:7"},
			},
		},
		{
			name:   "skips malformed lines",
			stdout: "abc123\tnginx:latest\ngarbage-no-tab\n\tno-id",
			want:   []containerRef{{ID: "abc123", Image: "nginx:latest"}},
		},
		{
			name:   "trims surrounding whitespace",
			stdout: "  abc123\tnginx:latest  \n",
			want:   []containerRef{{ID: "abc123", Image: "nginx:latest"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePS(tc.stdout)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d refs, want %d (%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ref[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
