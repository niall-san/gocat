package types

import (
	"encoding/json"
	"testing"
)

// TestStatus_NumericFieldsRoundTrip guards the additive numeric fields across a
// JSON round-trip: consumers transport Status as JSON and rely on these fields
// surviving unchanged. A decoder built against an older Status (without them)
// still decodes a newer payload — the fields are simply ignored — which is the
// backward-compatibility this change depends on.
func TestStatus_NumericFieldsRoundTrip(t *testing.T) {
	in := Status{
		ProgressMode: 1,
		Progress:     "123/456 (26.97%)",
		RestorePoint: "12/34 (35.29%)",
		ProgressCur:  123,
		ProgressEnd:  456,
		RestoreCur:   12,
		RestoreTotal: 34,
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out Status
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ProgressCur != 123 || out.ProgressEnd != 456 || out.RestoreCur != 12 || out.RestoreTotal != 34 {
		t.Fatalf("numeric fields did not round-trip: %+v", out)
	}
}

// TestStatus_UnknownKeyspaceHasNoEnd documents the contract consumers use to pick
// the ratio vs. the fallback: ProgressEnd == 0 means "unknown keyspace, no
// denominator". A zero end must survive the round-trip as zero (not dropped in a
// way that changes meaning).
func TestStatus_UnknownKeyspaceHasNoEnd(t *testing.T) {
	raw, err := json.Marshal(Status{ProgressCur: 999, ProgressEnd: 0})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Status
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ProgressEnd != 0 {
		t.Fatalf("ProgressEnd = %d, want 0 (unknown-keyspace sentinel)", out.ProgressEnd)
	}
}
