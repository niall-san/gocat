package gocat

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/niall-san/gocat/v6/hcargp"

	"github.com/stretchr/testify/require"
)

const (
	// Set this to true if you want the gocat callbacks used in the tests to print out
	DebugTest         bool   = true
	DefaultSharedPath string = "/usr/local/share/hashcat"
	DeviceType        string = "1"
)

type testStruct struct {
	opts          hcargp.HashcatSessionOptions
	expectedError error
}

func emptyCallback(hc unsafe.Pointer, payload interface{}) {}

func callbackForTests(resultsmap map[string]*string) EventCallback {
	return func(hc unsafe.Pointer, payload interface{}) {
		switch pl := payload.(type) {
		case LogPayload:
			if DebugTest {
				fmt.Printf("LOG [%s] %s\n", pl.Level, pl.Message)
			}
		case ActionPayload:
			if DebugTest {
				fmt.Printf("ACTION [%d] %s\n", pl.HashcatEvent, pl.Message)
			}
		case CrackedPayload:
			if DebugTest {
				fmt.Printf("CRACKED %s -> %s\n", pl.Hash, pl.Value)
			}
			if resultsmap != nil {
				resultsmap[pl.Hash] = hcargp.GetStringPtr(pl.Value)
			}
		case FinalStatusPayload:
			if DebugTest {
				fmt.Printf("FINAL STATUS -> %v\n", pl.Status)
			}
		case TaskInformationPayload:
			if DebugTest {
				fmt.Printf("TASK INFO -> %v\n", pl)
			}
		}
	}
}

func TestOptionsExecPath(t *testing.T) {
	// Valid
	opts := Options{
		ExecutablePath: "",
		SharedPath:     "/tmp",
	}

	err := opts.validate()
	require.Nil(t, err)

	require.True(t, strings.HasSuffix(opts.ExecutablePath, "test"))

	// Not valid because executable path was incorrectly set by the user
	opts.ExecutablePath = "/nope"
	err = opts.validate()
	require.Error(t, err)
}

func TestGoCatOptionsValidatorErrors(t *testing.T) {
	for _, test := range []struct {
		opts          Options
		expectedError error
		expectedOpts  map[string]interface{}
	}{
		{
			opts: Options{
				SharedPath: "",
			},
			expectedError: ErrNoSharedPath,
		},
		{
			opts: Options{
				SharedPath:     "/deadbeef",
				ExecutablePath: "",
			},
		},
	} {
		err := test.opts.validate()
		require.Equal(t, test.expectedError, err)
	}
}

func TestGoCatCrackingMD5(t *testing.T) {
	crackedHashes := map[string]*string{}

	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, callbackForTests(crackedHashes))
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.RunJob("-O", "-a", "0", "-m", "0", "-D", DeviceType, "--session", "test0", "--potfile-disable", "5d41402abc4b2a76b9719d911017c592", "./testdata/test_dictionary.txt")
	require.NoError(t, err)
	require.Len(t, crackedHashes, 1)
	require.Equal(t, "hello", *crackedHashes["5d41402abc4b2a76b9719d911017c592"])
}

func TestGoCatReusingContext(t *testing.T) {
	crackedHashes := map[string]*string{}

	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, callbackForTests(crackedHashes))
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.RunJob("-O", "-a", "0", "-m", "0", "-D", DeviceType, "--session", "test4", "--potfile-disable", "5d41402abc4b2a76b9719d911017c592", "./testdata/test_dictionary.txt")
	require.NoError(t, err)
	require.Len(t, crackedHashes, 1)
	require.Equal(t, "hello", *crackedHashes["5d41402abc4b2a76b9719d911017c592"])

	err = hc.RunJob("-O", "-a", "0", "-m", "0", "-D", DeviceType, "--session", "test5", "--potfile-disable", "9f9d51bc70ef21ca5c14f307980a29d8", "./testdata/test_dictionary.txt")
	require.NoError(t, err)
	require.Len(t, crackedHashes, 2) // the previous run will still exist in this map
	require.Equal(t, "bob", *crackedHashes["9f9d51bc70ef21ca5c14f307980a29d8"])
}

func TestGoCatRunJobWithOptions(t *testing.T) {
	crackedHashes := map[string]*string{}

	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, callbackForTests(crackedHashes))
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.RunJobWithOptions(hcargp.HashcatSessionOptions{
		OpenCLDeviceTypes:            hcargp.GetStringPtr(DeviceType),
		SessionName:                  hcargp.GetStringPtr("test3"),
		OptimizedKernelEnabled:       hcargp.GetBoolPtr(true),
		AttackMode:                   hcargp.GetIntPtr(0),
		HashType:                     hcargp.GetIntPtr(0),
		PotfileDisable:               hcargp.GetBoolPtr(true),
		InputFile:                    "9f9d51bc70ef21ca5c14f307980a29d8",
		DictionaryMaskDirectoryInput: hcargp.GetStringPtr("./testdata/test_dictionary.txt"),
	})

	require.NoError(t, err)
	require.Len(t, crackedHashes, 1) // the previous run will still exist in this map
	require.Equal(t, "bob", *crackedHashes["9f9d51bc70ef21ca5c14f307980a29d8"])
}

func TestGocatRussianHashes(t *testing.T) {
	crackedHashes := map[string]*string{}

	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, callbackForTests(crackedHashes))
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.RunJobWithOptions(hcargp.HashcatSessionOptions{
		OpenCLDeviceTypes:            hcargp.GetStringPtr(DeviceType),
		SessionName:                  hcargp.GetStringPtr("test1"),
		OptimizedKernelEnabled:       hcargp.GetBoolPtr(true),
		AttackMode:                   hcargp.GetIntPtr(0),
		HashType:                     hcargp.GetIntPtr(0),
		PotfileDisable:               hcargp.GetBoolPtr(true),
		InputFile:                    "./testdata/russian_test.hashes",
		DictionaryMaskDirectoryInput: hcargp.GetStringPtr("./testdata/russian_test.dictionary"),
	})

	require.NoError(t, err)
	require.Len(t, crackedHashes, 4) // the previous run will still exist in this map
}

func TestGoCatStopAtCheckpointWithNoRunningSession(t *testing.T) {
	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, emptyCallback)
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.StopAtCheckpoint()
	require.Equal(t, ErrUnableToStopAtCheckpoint, err)
}

func TestExampleHashcat_RunJobWithOptions(t *testing.T) {
	eventCallback := func(hc unsafe.Pointer, payload interface{}) {
		switch pl := payload.(type) {
		case LogPayload:
			if DebugTest {
				fmt.Printf("LOG [%s] %s\n", pl.Level, pl.Message)
			}
		case ActionPayload:
			if DebugTest {
				fmt.Printf("ACTION [%d] %s\n", pl.HashcatEvent, pl.Message)
			}
		case CrackedPayload:
			if DebugTest {
				fmt.Printf("CRACKED %s -> %s\n", pl.Hash, pl.Value)
			}
		case FinalStatusPayload:
			if DebugTest {
				fmt.Printf("FINAL STATUS -> %v\n", pl.Status)
			}
		case TaskInformationPayload:
			if DebugTest {
				fmt.Printf("TASK INFO -> %v\n", pl)
			}
		}
	}

	hc, err := New(Options{
		SharedPath:     "/usr/local/share/hashcat",
		ExecutablePath: "/usr/local/share/hashcat",
	}, eventCallback)
	defer hc.Free()

	if err != nil {
		log.Fatal(err)
	}

	err = hc.RunJobWithOptions(hcargp.HashcatSessionOptions{
		OpenCLDeviceTypes:            hcargp.GetStringPtr(DeviceType),
		SessionName:                  hcargp.GetStringPtr("test2"),
		AttackMode:                   hcargp.GetIntPtr(0),
		HashType:                     hcargp.GetIntPtr(0),
		PotfileDisable:               hcargp.GetBoolPtr(true),
		OptimizedKernelEnabled:       hcargp.GetBoolPtr(true),
		InputFile:                    "9f9d51bc70ef21ca5c14d307980a29d2",
		DictionaryMaskDirectoryInput: hcargp.GetStringPtr("./testdata/test_dictionary.txt"),
	})

	if err != nil {
		log.Fatal(err)
	}
}

func TestHashIdentify(t *testing.T) {

	opts := Options{
		SharedPath: DefaultSharedPath,
	}

	types, err := IdentifyHash("5d41402abc4b2a76b9719d911017c592", opts)
	require.Len(t, types, 11)
	require.NoError(t, err)

	invalidHash, err := IdentifyHash("5d4'[##'[]]'1017c592", opts)
	require.Error(t, err)
	require.Nil(t, invalidHash)
}

func TestGoCatHccapx(t *testing.T) {
	crackedHashes := map[string]*string{}

	hc, err := New(Options{
		SharedPath: DefaultSharedPath,
	}, callbackForTests(crackedHashes))
	defer hc.Free()

	require.NotNil(t, hc)
	require.NoError(t, err)

	err = hc.RunJobWithOptions(hcargp.HashcatSessionOptions{
		OpenCLDeviceTypes:            hcargp.GetStringPtr(DeviceType),
		SessionName:                  hcargp.GetStringPtr("test6"),
		OptimizedKernelEnabled:       hcargp.GetBoolPtr(true),
		AttackMode:                   hcargp.GetIntPtr(0),
		HashType:                     hcargp.GetIntPtr(2500),
		PotfileDisable:               hcargp.GetBoolPtr(true),
		EnableDeprecated:             hcargp.GetBoolPtr(true),
		InputFile:                    "./testdata/hashcat.hccapx",
		DictionaryMaskDirectoryInput: hcargp.GetStringPtr("./testdata/test_dictionary.txt"),
	})

	fmt.Printf("crackedHashes: %v\n", crackedHashes)

	require.NoError(t, err)
	require.Len(t, crackedHashes, 1)
}

func TestCustomCommandLine(t *testing.T) {
	options, err := hcargp.ParseOptions("--optimized-kernel-enable=true --custom-charset1=DEADBEEF --attack-mode=0 --hash-type=0 --potfile-disable=true")

	require.NoError(t, err)
	require.NotNil(t, options)

	//PrintOptions(options)

	errorOptions, err := hcargp.ParseOptions("--invalid-option --optimized-kernel-enable=true --custom-charset1=DEADBEEF")

	require.Error(t, err)
	require.Nil(t, errorOptions)

	missingDashOptions, err := hcargp.ParseOptions("thisisatest --optimized-kernel-enable=true --custom-charset1=DEADBEEF")
	require.Error(t, err)
	require.Nil(t, missingDashOptions)

}

// helper function to print out the options
func PrintOptions(options *hcargp.HashcatSessionOptions) {
	v := reflect.ValueOf(options).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		name := v.Type().Field(i).Name

		if field.Kind() == reflect.Ptr && !field.IsNil() {
			field = field.Elem()
		}

		fmt.Printf("%s: %v\n", name, field.Interface())
	}
}
