package types

import (
	"fmt"
	"time"
)

const (
	// InfoMessage is a log message from hashcat with the id of EVENT_LOG_INFO
	InfoMessage LogLevel = iota
	// WarnMessage is a log message from hashcat with the id of EVENT_LOG_WARNING
	WarnMessage
	// ErrorMessage is a log message from hashcat with the id of EVENT_LOG_ERROR
	ErrorMessage
	// AdviceMessage is a log message from hashcat with the id of EVENT_LOG_ADVICE
	AdviceMessage
)

// LogPayload defines the structure of an event log message from hashcat and sent to the user via the callback
type LogPayload struct {
	Level   LogLevel
	Message string
	Error   error
}

// TaskInformationPayload includes information about the task that hashcat is getting ready to process. This includes deduplicated hashes, etc.
type TaskInformationPayload struct {
	NumHashes       uint32
	NumHashesUnique uint32
	NumSalts        uint32
}

// ActionPayload defines the structure of a generic hashcat event and sent to the user via the callback.
// An example of this would be the numerous PRE/POST events.
type ActionPayload struct {
	HashcatEvent uint32
	LogPayload
}

// CrackedPayload defines the structure of a cracked message from hashcat and sent to the user via the callback
type CrackedPayload struct {
	IsPotfile bool
	Hash      string
	Value     string
	CrackedAt time.Time
}

// FinalStatusPayload is returned at the end of the cracking session
type FinalStatusPayload struct {
	Status  *Status
	EndedAt time.Time
	// AllHashesCracked is set when all hashes either exist in a potfile or are considered "weak"
	AllHashesCracked bool
}

// ErrCrackedPayload is raised whenever we get a cracked password callback but was unable to parse the message from hashcat
type ErrCrackedPayload struct {
	Separator  string
	CrackedMsg string
}

func (e ErrCrackedPayload) Error() string {
	return fmt.Sprintf("Could not locate separator `%s` in msg", e.Separator)
}

// LogLevel indicates the type of log message from hashcat
type LogLevel int8

func (s LogLevel) String() string {
	switch s {
	case InfoMessage:
		return "INFO"
	case WarnMessage:
		return "WARN"
	case ErrorMessage:
		return "ERROR"
	case AdviceMessage:
		return "ADVICE"
	default:
		return "UNKNOWN"
	}
}
