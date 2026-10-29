package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupportedHashesAreUnique(t *testing.T) {
	seen := map[int]bool{}
	for _, h := range SupportedHashes() {
		require.False(t, seen[h.Type], "duplicate hash-mode %d", h.Type)
		require.NotEmpty(t, h.Name, "hash-mode %d has no name", h.Type)
		seen[h.Type] = true
	}
	require.True(t, seen[0], "MD5 (0) missing")
	require.True(t, seen[1000], "NTLM (1000) missing")
}

func TestLegacyHashModesPointAtSupportedModes(t *testing.T) {
	supported := map[int]bool{}
	for _, h := range SupportedHashes() {
		supported[h.Type] = true
	}

	require.NotEmpty(t, LegacyHashModes())
	for oldMode, newMode := range LegacyHashModes() {
		require.False(t, supported[oldMode], "retired hash-mode %d is still listed", oldMode)
		require.True(t, supported[newMode], "hash-mode %d replaces %d but is not listed", newMode, oldMode)
	}
}
