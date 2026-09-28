package gocat

// #include "wrapper.h"
import "C"
import (
	"strings"
	"time"
	"unsafe"

	"github.com/niall-san/gocat/v7/types"
)

// The payload and log types are declared in the cgo-free types package so that
// consumers can use them without linking libhashcat. These aliases keep the
// existing gocat API unchanged.
type (
	// LogLevel indicates the type of log message from hashcat
	LogLevel = types.LogLevel
	// LogPayload defines the structure of an event log message from hashcat and sent to the user via the callback
	LogPayload = types.LogPayload
	// TaskInformationPayload includes information about the task that hashcat is getting ready to process
	TaskInformationPayload = types.TaskInformationPayload
	// ActionPayload defines the structure of a generic hashcat event and sent to the user via the callback
	ActionPayload = types.ActionPayload
	// CrackedPayload defines the structure of a cracked message from hashcat and sent to the user via the callback
	CrackedPayload = types.CrackedPayload
	// FinalStatusPayload is returned at the end of the cracking session
	FinalStatusPayload = types.FinalStatusPayload
	// ErrCrackedPayload is raised whenever we get a cracked password callback but was unable to parse the message from hashcat
	ErrCrackedPayload = types.ErrCrackedPayload
)

const (
	// InfoMessage is a log message from hashcat with the id of EVENT_LOG_INFO
	InfoMessage = types.InfoMessage
	// WarnMessage is a log message from hashcat with the id of EVENT_LOG_WARNING
	WarnMessage = types.WarnMessage
	// ErrorMessage is a log message from hashcat with the id of EVENT_LOG_ERROR
	ErrorMessage = types.ErrorMessage
	// AdviceMessage is a log message from hashcat with the id of EVENT_LOG_ADVICE
	AdviceMessage = types.AdviceMessage
)

// logMessageCbFromEvent is called whenever hashcat sends a INFO/WARN/ERROR message
func logMessageCbFromEvent(ctx *C.hashcat_ctx_t, lvl LogLevel) LogPayload {
	// In hashcat 7.x+, ctx or ctx.event_ctx may be null for log events
	// In such cases, the message should be retrieved from the buf parameter
	// in the callback function instead
	if ctx == nil {
		return LogPayload{
			Level:   lvl,
			Message: "",
		}
	}

	ectx := ctx.event_ctx
	if ectx == nil {
		return LogPayload{
			Level:   lvl,
			Message: "",
		}
	}

	return LogPayload{
		Level:   lvl,
		Message: C.GoStringN(&ectx.msg_buf[0], C.int(ectx.msg_len)),
	}
}

// logMessageFromBuffer creates a log message from a buffer (used in hashcat 7.x+ when ctx is null)
func logMessageFromBuffer(buf unsafe.Pointer, lvl LogLevel) LogPayload {
	var msg string
	if buf != nil {
		msg = C.GoString((*C.char)(buf))
	}
	return LogPayload{
		Level:   lvl,
		Message: msg,
	}
}

func logMessageWithError(id uint32, err error) LogPayload {
	return LogPayload{
		Level:   ErrorMessage,
		Message: err.Error(),
		Error:   err,
	}
}

func logHashcatAction(id uint32, msg string) ActionPayload {
	return ActionPayload{
		LogPayload: LogPayload{
			Level:   InfoMessage,
			Message: msg,
		},
		HashcatEvent: id,
	}
}

func getCrackedPassword(id uint32, msg string, sep string) (pl CrackedPayload, err error) {
	// Some messages can have multiple variations of the separator (example: kerberos 13100)
	// so we find the last one and use that to separate the original hash and it's value
	idx := strings.LastIndex(msg, sep)
	if idx == -1 {
		err = ErrCrackedPayload{
			Separator:  sep,
			CrackedMsg: msg,
		}
		return
	}

	pl = CrackedPayload{
		Hash:      msg[:idx],
		Value:     msg[idx+1:],
		IsPotfile: id == C.EVENT_POTFILE_HASH_SHOW,
		CrackedAt: time.Now().UTC(),
	}
	return
}
