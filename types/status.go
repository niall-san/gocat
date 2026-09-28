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
	GuessMode             int
	GuessMask             string `json:",omitempty"`
	GuessQueue            string `json:",omitempty"`
	GuessBase             string `json:",omitempty"`
	GuessMod              string `json:",omitempty"`
	GuessCharset          string `json:",omitempty"`
}
