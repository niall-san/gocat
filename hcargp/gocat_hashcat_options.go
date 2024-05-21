package hcargp

import (
	"flag"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
)

// GetStringPtr returns the pointer of s
func GetStringPtr(s string) *string {
	return &s
}

// GetIntPtr returns the pointer of i
func GetIntPtr(i int) *int {
	return &i
}

// GetBoolPtr returns the pointer of b
func GetBoolPtr(b bool) *bool {
	return &b
}

/*
We skip the following arguments because they are not needed:
- version
- help
- quiet
- status
- status-timer
- machine-readable
- stdout
- show
- left
- benchmark
- speed-only (todo?)
- progress-only (todo?)
- opencl-info
- keyspace
*/

// HashcatSessionOptions represents all the available hashcat options. The values here should always follow the latest version of hashcat
type HashcatSessionOptions struct {
	HashType               *int    `hashcat:"--hash-type,omitempty"`
	AttackMode             *int    `hashcat:"--attack-mode,omitempty"`
	IsHexCharset           *bool   `hashcat:"--hex-charset,omitempty"`
	IsHexSalt              *bool   `hashcat:"--hex-salt,omitempty"`
	IsHexWordlist          *bool   `hashcat:"--hex-wordlist,omitempty"`
	KeepGuessing           *bool   `hashcat:"--keep-guessing,omitempty"`
	Loopback               *bool   `hashcat:"--loopback,omitempty"`
	WeakHashThreshold      *int    `hashcat:"--weak-hash-threshold,omitempty"`
	MarkovHCStat           *string `hashcat:"--markov-hcstat,omitempty"`
	DisableMarkov          *bool   `hashcat:"--markov-disable,omitempty"`
	EnableClassicMarkov    *bool   `hashcat:"--markov-classic,omitempty"`
	MarkovThreshold        *int    `hashcat:"--markov-threshold,omitempty"`
	Force                  *bool   `hashcat:"--force,omitempty"`
	MaxRuntimeSeconds      *int    `hashcat:"--runtime,omitempty"`
	SessionName            *string `hashcat:"--session,omitempty"`
	RestoreSession         *bool   `hashcat:"--restore,omitempty"`
	DisableRestore         *bool   `hashcat:"--restore-disable,omitempty"`
	RestoreFilePath        *string `hashcat:"--restore-file-path,omitempty"`
	OutfilePath            *string `hashcat:"--outfile,omitempty"`
	OutfileFormat          *int    `hashcat:"--outfile-format,omitempty"`
	OutfileDisableAutoHex  *bool   `hashcat:"--outfile-autohex-disable,omitempty"`
	OutfileCheckTimer      *int    `hashcat:"--outfile-check-timer,omitempty"`
	Separator              *string `hashcat:"--separator,omitempty"`
	IgnoreUsername         *bool   `hashcat:"--username,omitempty"`
	RemoveCrackedHash      *bool   `hashcat:"--remove,omitempty"`
	RemoveCrackedHashTimer *int    `hashcat:"--remove-timer,omitempty"`
	PotfileDisable         *bool   `hashcat:"--potfile-disable,omitempty"`
	PotfilePath            *string `hashcat:"--potfile-path,omitempty"`
	EncodingFrom           *string `hashcat:"--encoding-from,omitempty"`
	EncodingTo             *string `hashcat:"--encoding-to,omitempty"`
	DebugMode              *int    `hashcat:"--debug-mode,omitempty"`
	DebugFile              *string `hashcat:"--debug-file,omitempty"`
	InductionDir           *string `hashcat:"--induction-dir,omitempty"`
	LogfileDisable         *bool   `hashcat:"--logfile-disable,omitempty"`
	HccapxMessagePair      *string `hashcat:"--hccapx-message-pair,omitempty"`
	NonceErrorCorrections  *int    `hashcat:"--nonce-error-corrections,omitempty"`
	TrueCryptKeyFiles      *string `hashcat:"--truecrypt-keyfiles,omitempty"`
	VeraCryptKeyFiles      *string `hashcat:"--veracrypt-keyfiles,omitempty"`
	VeraCryptPIM           *int    `hashcat:"--veracrypt-pim,omitempty"`
	VeraCryptPIMStart      *int    `hashcat:"--veracrypt-pim-start,omitempty"`
	VeraCryptPIMStop       *int    `hashcat:"--veracrypt-pim-stop,omitempty"`
	SegmentSize            *int    `hashcat:"--segment-size,omitempty"`
	BitmapMin              *int    `hashcat:"--bitmap-min,omitempty"`
	BitmapMax              *int    `hashcat:"--bitmap-max,omitempty"`
	CPUAffinity            *string `hashcat:"--cpu-affinity,omitempty"`
	HookThreads            *int    `hashcat:"--hook-threads,omitempty"`
	BackendIgnoreCUDA      *bool   `hashcat:"--backend-ignore-cuda,omitempty"`
	BackendIgnoreOpenCL    *bool   `hashcat:"--backend-ignore-opencl,omitempty"`
	BackendDevices         *string `hashcat:"--backend-devices,omitempty"`
	OpenCLDeviceTypes      *string `hashcat:"--opencl-device-types,omitempty"`
	OptimizedKernelEnabled *bool   `hashcat:"--optimized-kernel-enable,omitempty"`
	WorkloadProfile        *int    `hashcat:"--workload-profile,omitempty"`
	KernelAccel            *int    `hashcat:"--kernel-accel,omitempty"`
	KernelLoops            *int    `hashcat:"--kernel-loops,omitempty"`
	SpinDamp               *int    `hashcat:"--spin-damp,omitempty"`
	HWMonitorDisable       *bool   `hashcat:"--hwmon-disable,omitempty"`
	HWMonitorTempAbort     *int    `hashcat:"--hwmon-temp-abort,omitempty"`
	ScryptTMTO             *int    `hashcat:"--scrypt-tmto,omitempty"`
	Skip                   *int    `hashcat:"--skip,omitempty"`
	Limit                  *int    `hashcat:"--limit,omitempty"`
	RuleLeft               *string `hashcat:"--rule-left,omitempty"`
	RuleRight              *string `hashcat:"--rule-right,omitempty"`
	RulesFile              *string `hashcat:"--rules-file,omitempty"`
	GenerateRules          *int    `hashcat:"--generate-rules,omitempty"`
	GenerateRulesFuncMin   *int    `hashcat:"--generate-rules-func-min,omitempty"`
	GenerateRulesFuncMax   *int    `hashcat:"--generate-rules-func-max,omitempty"`
	GenerateRulesSeed      *int    `hashcat:"--generate-rules-seed,omitempty"`
	CustomCharset1         *string `hashcat:"--custom-charset1,omitempty"`
	CustomCharset2         *string `hashcat:"--custom-charset2,omitempty"`
	CustomCharset3         *string `hashcat:"--custom-charset3,omitempty"`
	CustomCharset4         *string `hashcat:"--custom-charset4,omitempty"`
	IncrementMask          *bool   `hashcat:"--increment,omitempty"`
	IncrementMaskMin       *int    `hashcat:"--increment-min,omitempty"`
	IncrementMaskMax       *int    `hashcat:"--increment-max,omitempty"`
	Identify               *bool   `hashcat:"--identify,omitempty"`
	EnableDeprecated       *bool   `hashcat:"--deprecated-check-disable,omitempty"`

	// InputFile can be a single hash or multiple hashes via a hashfile or hccapx
	InputFile                    string  `hashcat:","`
	DictionaryMaskDirectoryInput *string `hashcat:",omitempty"`
}

func parseTag(t string) (tag, options string) {
	if idx := strings.Index(t, ","); idx != -1 {
		return t[:idx], t[idx+1:]
	}
	return tag, ""
}

// ParseOptions parses the options string and returns a HashcatSessionOptions struct
func ParseOptions(optionsString string) (*HashcatSessionOptions, error) {
	options := &HashcatSessionOptions{}
	flagSet := flag.NewFlagSet("hashcat", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	v := reflect.ValueOf(options).Elem()
	t := v.Type()

	flagNames := make([]string, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := t.Field(i).Tag.Get("hashcat")

		if tag == "" || !field.CanSet() {
			continue
		}

		name := strings.Split(tag, ",")[0]
		name = strings.TrimPrefix(name, "--")
		flagNames[i] = name

		switch field.Kind() {
		case reflect.Ptr:
			switch field.Type().Elem().Kind() {
			case reflect.Int:
				field.Set(reflect.ValueOf(flagSet.Int(name, 0, "")))
			case reflect.Bool:
				field.Set(reflect.ValueOf(flagSet.Bool(name, false, "")))
			case reflect.String:
				field.Set(reflect.ValueOf(flagSet.String(name, "", "")))
			}
		}
	}

	args := strings.Fields(optionsString)
	err := flagSet.Parse(args)
	if err != nil {
		return nil, err
	}

	for i, name := range flagNames {
		if name != "" && !isFlagPassed(flagSet, name) {
			v.Field(i).Set(reflect.Zero(v.Field(i).Type()))
		}
	}

	return options, nil
}

func isFlagPassed(flagSet *flag.FlagSet, name string) bool {
	found := false
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// MarshalArgs returns a list of arguments set by the user to be passed into hashcat's session for execution
func (o HashcatSessionOptions) MarshalArgs() (args []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if s, ok := r.(string); ok {
				panic(s)
			}

			err = r.(error)
		}
	}()

	v := reflect.ValueOf(o)
	for i := 0; i < v.NumField(); i++ {
		tag := v.Type().Field(i).Tag.Get("hashcat")
		if tag == "" {
			continue
		}

		name, opts := parseTag(tag)
		val := v.Field(i)

		hasOmitEmpty := strings.Contains(opts, "omitempty")
		if (val.Type().Kind() == reflect.Ptr && val.IsNil()) && hasOmitEmpty {
			continue
		}

		if val.Type().Kind() == reflect.Ptr {
			val = reflect.Indirect(val)
		}

		switch val.Type().Kind() {
		case reflect.Bool:
			if val.Bool() {
				args = append(args, name)
			}
		case reflect.Int:
			// Int's should always have a name...
			if name != "" {
				args = append(args, fmt.Sprintf("%s=%d", name, val.Int()))
			}
		case reflect.String:
			if val.String() == "" {
				continue
			}

			if name != "" {
				args = append(args, fmt.Sprintf("%s=%s", name, val.String()))
			} else {
				args = append(args, val.String())
			}
		default:
			err = fmt.Errorf("unknown type %s", val.Type().Kind())
			return
		}
	}
	return
}
