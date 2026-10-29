//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// rxpModuleAlias matches an entry of hashcat's module_aliases table in src/interface.c,
// which maps a retired hash-mode number to the number that replaced it.
var rxpModuleAlias = regexp.MustCompile(`\{\s*(\d+)\s*,\s*(\d+)\s*\}\s*,`)

type hashInfo struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	ExampleHash string `json:"example_hash"`
}

type hash struct {
	Name     string
	Type     int
	Category string
	Example  string
}

// loadHashes runs `hashcat --hash-info --machine-readable` and returns every hash-mode it reports.
func loadHashes(hashcatBin string) ([]hash, error) {
	cmd := exec.Command(hashcatBin, "--hash-info", "--machine-readable")
	cmd.Dir = filepath.Dir(hashcatBin)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running %s: %w", hashcatBin, err)
	}

	// hashcat prints a banner line before the JSON document
	start := bytes.IndexByte(out, '{')
	if start == -1 {
		return nil, fmt.Errorf("no JSON in %s output", hashcatBin)
	}

	var infos map[string]hashInfo
	if err := json.Unmarshal(out[start:], &infos); err != nil {
		return nil, fmt.Errorf("parsing hash info: %w", err)
	}

	hashes := make([]hash, 0, len(infos))
	for mode, info := range infos {
		hashType, err := strconv.Atoi(mode)
		if err != nil {
			return nil, fmt.Errorf("invalid hash-mode %q: %w", mode, err)
		}

		example := info.ExampleHash
		if example == "N/A" {
			example = ""
		}

		hashes = append(hashes, hash{Name: info.Name, Type: hashType, Category: info.Category, Example: example})
	}

	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Type < hashes[j].Type })
	return hashes, nil
}

// loadAliases reads the retired-to-current hash-mode table from hashcat's src/interface.c.
func loadAliases(srcPath string) (map[int]int, error) {
	buf, err := os.ReadFile(filepath.Join(srcPath, "src", "interface.c"))
	if err != nil {
		return nil, err
	}

	aliases := map[int]int{}
	for _, m := range rxpModuleAlias.FindAllSubmatch(buf, -1) {
		oldMode, _ := strconv.Atoi(string(m[1]))
		newMode, _ := strconv.Atoi(string(m[2]))
		aliases[oldMode] = newMode
	}
	return aliases, nil
}

func main() {
	hashcatBin := os.Getenv("HASHCAT_BIN")
	srcPath := os.Getenv("HASHCAT_SRC_PATH")
	if hashcatBin == "" || srcPath == "" {
		log.Fatal("HASHCAT_BIN must be set to a hashcat binary and HASHCAT_SRC_PATH to the matching hashcat source tree")
	}

	hashes, err := loadHashes(hashcatBin)
	if err != nil {
		log.Fatal(err)
	}

	aliases, err := loadAliases(srcPath)
	if err != nil {
		log.Fatalf("Could not read hash-mode aliases: %s", err)
	}

	oldModes := make([]int, 0, len(aliases))
	for oldMode := range aliases {
		oldModes = append(oldModes, oldMode)
	}
	sort.Ints(oldModes)

	b := new(bytes.Buffer)
	b.WriteString("// Code automatically generated; DO NOT EDIT.\n\n")
	b.WriteString("package types\n\n")
	b.WriteString("// Hash describes information about supported file hashes\n")
	b.WriteString("type Hash struct {\n\tName string\n\tExample string\n\tCategory string\n\tType int\n}\n\n")

	b.WriteString("var hashes = []Hash{\n")
	for _, h := range hashes {
		b.WriteString("\t{\n")
		fmt.Fprintf(b, "\t Name: %s,\n", strconv.Quote(h.Name))
		fmt.Fprintf(b, "\t Type: %d,\n", h.Type)
		fmt.Fprintf(b, "\t Category: %s,\n", strconv.Quote(h.Category))
		if h.Example != "" {
			fmt.Fprintf(b, "\t Example: %s,\n", strconv.Quote(h.Example))
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n\n")

	b.WriteString("var legacyHashModes = map[int]int{\n")
	for _, oldMode := range oldModes {
		fmt.Fprintf(b, "\t%d: %d,\n", oldMode, aliases[oldMode])
	}
	b.WriteString("}\n\n")

	b.WriteString("// SupportedHashes returns a list of available hashes supported by Hashcat\n")
	b.WriteString("func SupportedHashes() []Hash {\n\t return hashes\n}\n\n")
	b.WriteString("// LegacyHashModes maps retired hash-mode numbers to the numbers that replaced them.\n")
	b.WriteString("// Hashcat still accepts a retired number with -m, but no longer lists it.\n")
	b.WriteString("func LegacyHashModes() map[int]int {\n\t return legacyHashModes\n}\n")

	formattedSource, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("Could not format generated source: %s", err)
	}

	if err := os.WriteFile("./hash_types.go", formattedSource, 0o644); err != nil {
		log.Fatalf("Could not write destination file: %s", err)
	}
}
