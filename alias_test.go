package gocat

import (
	"testing"

	"github.com/niall-san/gocat/v7/types"
)

// TestTypesAreAliases proves the root-package names are aliases of the types
// package, not copies: assignment between distinct named types would not compile.
func TestTypesAreAliases(t *testing.T) {
	var s types.Status = Status{Session: "s"}
	var _ Status = s
	var _ types.DeviceStatus = DeviceStatus{}
	var _ types.FinalStatusPayload = FinalStatusPayload{Status: &s}
	var _ types.ActionPayload = ActionPayload{LogPayload: LogPayload{Level: WarnMessage}}
	var _ types.CrackedPayload = CrackedPayload{}
	var _ types.TaskInformationPayload = TaskInformationPayload{}
	var _ error = ErrCrackedPayload{}
	var _ types.LogLevel = AdviceMessage

	if WarnMessage.String() != "WARN" {
		t.Fatalf("LogLevel.String lost in move: %q", WarnMessage.String())
	}
}
