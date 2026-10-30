package types

// DeviceStatus contains information about the OpenCL device that is cracking
type DeviceStatus struct {
	DeviceID  int
	HashesSec string
	ExecDev   float64
}

// Status contains data about the current cracking session
type Status struct {
	Session               string
	Status                string
	HashType              string
	HashTarget            string
	TimeStarted           string
	TimeEstimated         string
	TimeEstimatedRelative string
	DeviceStatus          []DeviceStatus
	TotalSpeed            string
	ProgressMode          int
	Candidates            map[int]string // map[DeviceID]string
	Progress              string
	Rejected              string
	Recovered             string
	RestorePoint          string
	// Numeric counterparts of the formatted fields above, exposed so consumers
	// can do arithmetic without re-parsing the display strings. All are in
	// hashcat's relative-skip space (the current attack's keyspace, honoring
	// --skip/--limit). ProgressCur/ProgressEnd are amplified candidate units
	// (base × salts × rules/combs/bfs); their ratio is the fraction of the
	// attack completed. RestoreCur/RestoreTotal are base-word units. ProgressEnd
	// is 0 when the keyspace is unknown (stdin/grammar), signalling no ratio.
	ProgressCur  uint64
	ProgressEnd  uint64
	RestoreCur   uint64
	RestoreTotal uint64
	GuessMode    int
	GuessMask    string `json:",omitempty"`
	GuessQueue   string `json:",omitempty"`
	GuessBase    string `json:",omitempty"`
	GuessMod     string `json:",omitempty"`
	GuessCharset string `json:",omitempty"`
}
