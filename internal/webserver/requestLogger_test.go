package webserver

import (
	"regexp"
	"testing"
)

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"letters", "trace", true},
		{"digits", "123456", true},
		{"mixed", "req777ABC", true},
		{"uuid without hyphens", "550e8400e29b41d4a716446655440000", true},
		{"uppercase", "ABCDEF0123456789", true},
		{"empty", "", false},
		{"hyphen", "trace-123", false},
		{"underscore", "trace_123", false},
		{"space", "trace 123", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlphanumeric(tc.in); got != tc.want {
				t.Errorf("isAlphanumeric(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestMaxRequestIdLengthMatchesACanonicalUuid(t *testing.T) {
	if len("550e8400-e29b-41d4-a716-446655440000") > maxRequestIdLength {
		t.Errorf("maxRequestIdLength = %d, want at least a canonical UUID", maxRequestIdLength)
	}
	if len("01ARZ3NDEKTSV4RRFFQ69G5FAV") > maxRequestIdLength {
		t.Errorf("maxRequestIdLength = %d, want at least a ULID", maxRequestIdLength)
	}
}

func TestNewRequestIdIsUuidV4(t *testing.T) {
	for i := 0; i < 50; i++ {
		if id := newRequestId(); !uuidV4Pattern.MatchString(id) {
			t.Fatalf("newRequestId() = %q, want a UUID v4", id)
		}
	}
}
