//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/format"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	rxpHashName     = regexp.MustCompile(`static const char \*HASH_NAME\s+=\s+\"(.*?)\";`)
	rxpKernelType   = regexp.MustCompile(`static const u64\s+KERN_TYPE\s+=\s+(.*?);`)
	rxpExampleHash  = regexp.MustCompile(`static const char\s+\*ST_HASH\s+=\s+"(.*?)\";`)
	rxpHashCategory = regexp.MustCompile(`static const u32\s+HASH_CATEGORY\s+=\s+(HASH_CATEGORY_[A-Z_]+);`)
)

func locateHashName(buff []byte) string {
	matches := rxpHashName.FindSubmatch(buff)
	if len(matches) != 2 {
		return ""
	}

	return string(matches[1])
}

func locateHashCategory(buff []byte) string {
	matches := rxpHashCategory.FindSubmatch(buff)
	if len(matches) != 2 {
		return ""
	}

	categoryString, found := hashCategoryLookup[string(matches[1])]
	if !found {
		log.Printf("Invalid category")
		return ""
	}

	return categoryString
}

func locateKernelType(buff []byte) (int, error) {
	matches := rxpKernelType.FindSubmatch(buff)
	if len(matches) != 2 {
		return 0, errors.New("could not locate kernel type")
	}

	return strconv.Atoi(string(matches[1]))
}

func locateExample(buff []byte) string {
	matches := rxpExampleHash.FindSubmatch(buff)
	if len(matches) != 2 {
		return ""
	}

	return string(matches[1])
}

type customHash struct {
	Name     string
	Type     int
	Example  string
	Category string
}

var hashCategoryLookup = map[string]string{
	"HASH_CATEGORY_UNDEFINED":              "Undefined",
	"HASH_CATEGORY_RAW_HASH":               "Raw Hash",
	"HASH_CATEGORY_RAW_HASH_SALTED":        "Raw Hash, Salted and/or Iterated",
	"HASH_CATEGORY_RAW_HASH_AUTHENTICATED": "Raw Hash, Authenticated",
	"HASH_CATEGORY_RAW_CIPHER_KPA":         "Raw Cipher, Known-Plaintext attack",
	"HASH_CATEGORY_GENERIC_KDF":            "Generic KDF",
	"HASH_CATEGORY_NETWORK_PROTOCOL":       "Network Protocols",
	"HASH_CATEGORY_FORUM_SOFTWARE":         "Forums, CMS, E-Commerce",
	"HASH_CATEGORY_DATABASE_SERVER":        "Database Server",
	"HASH_CATEGORY_NETWORK_SERVER":         "FTP, HTTP, SMTP, LDAP Server",
	"HASH_CATEGORY_RAW_CHECKSUM":           "Raw Checksum",
	"HASH_CATEGORY_OS":                     "Operating System",
	"HASH_CATEGORY_EAS":                    "Enterprise Application Software (EAS)",
	"HASH_CATEGORY_ARCHIVE":                "Archives",
	"HASH_CATEGORY_FDE":                    "Full-Disk Encryption (FDE)",
	"HASH_CATEGORY_DOCUMENTS":              "Documents",
	"HASH_CATEGORY_PASSWORD_MANAGER":       "Password Managers",
	"HASH_CATEGORY_OTP":                    "One-Time Passwords",
	"HASH_CATEGORY_PLAIN":                  "Plaintext",
	"HASH_CATEGORY_FRAMEWORK":              "Framework",
	"HASH_CATEGORY_PRIVATE_KEY":            "Private Key",
	"HASH_CATEGORY_IMS":                    "Instant Messaging Service",
	"HASH_CATEGORY_CRYPTOCURRENCY_WALLET":  "Cryptocurrency Wallet",
	"HASH_CATEGORY_FBE":                    "File-Based Encryption (FBE)",
	"HASH_CATEGORY_APPLICATION_DATABASE":   "Application Database",
}

var knownDynamic = map[int][]customHash{
	16511: []customHash{
		{
			Name: "JWT (JSON Web Token) HS256",
			Type: 16511,
		},
		{
			Name: "JWT (JSON Web Token) HS384",
			Type: 16512,
		},
		{
			Name: "JWT (JSON Web Token) HS512",
			Type: 16513,
		},
	},
}

func checkNameModule(name string) (int, error) {
	if !strings.HasPrefix(name, "module_") {
		return 0, fmt.Errorf("%s does not appear to be a hashcat module", name)
	}

	// The string minus module_ prefix and .c suffix
	mod := name[7 : len(name)-2]

	// Special case for the 0 module
	if mod == "00000" {
		return 0, nil
	}

StripZeros:
	for i, r := range mod {
		if r != 0x30 {
			mod = mod[i:]
			break StripZeros
		}
	}

	return strconv.Atoi(mod)
}

func main() {
	srcPath := os.Getenv("HASHCAT_SRC_PATH")
	if srcPath == "" {
		log.Fatal("HASHCAT_SRC_PATH must be set to hashcat's src/modules directory to generate code")
	}

	b := new(bytes.Buffer)
	b.WriteString("// Code automatically generated; DO NOT EDIT.\n")
	b.WriteString("\n")
	b.WriteString("package types")
	b.WriteString("\n")
	b.WriteString("// Hash describes information about supported file hashes\n")
	b.WriteString("type Hash struct {\n")
	b.WriteString("\tName string\n")
	b.WriteString("\tExample string\n")
	b.WriteString("\tCategory string\n")
	b.WriteString("\tType int\n")
	b.WriteString("}\n")
	b.WriteString("var hashes = []Hash{\n")

	filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		bytez, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatalf(err.Error())
		}

		hashName := locateHashName(bytez)
		if hashName == "" {
			log.Fatalf("Could not locate hash name in %s", info.Name())
		}

		hashCategory := locateHashCategory(bytez)
		if hashCategory == "" {
			log.Fatalf("Could not locate hash category in %s", info.Name())
		}

		kernelType, err := locateKernelType(bytez)
		if err != nil {
			log.Fatalf("Could not locate kernel type in %s", info.Name())
		}

		kernTypeFromFn, err := checkNameModule(info.Name())
		if err != nil {
			log.Fatalf("Could not locate kernel type in %s", info.Name())
		}

		if kernTypeFromFn != kernelType {
			log.Printf("WRN: Filename Contains Kernel Version %d but KERN_TYPE constant reports %d", kernTypeFromFn, kernelType)
			kernelType = kernTypeFromFn
		}

		example := locateExample(bytez)

		if dyn, ok := knownDynamic[kernelType]; ok {
			for _, hashType := range dyn {
				b.WriteString("\t{\n")
				b.WriteString(fmt.Sprintf("\t Name: \"%s\",\n", hashType.Name))
				b.WriteString(fmt.Sprintf("\t Type: %d,\n", hashType.Type))
				b.WriteString(fmt.Sprintf("\t Category: \"%s\",\n", hashType.Category))

				if hashType.Example != "" {
					b.WriteString(fmt.Sprintf("\t Example: \"%s\",\n", hashType.Example))
				} else if hashType.Example == "" && example != "" {
					b.WriteString(fmt.Sprintf("\t Example: \"%s\",\n", example))
				}

				b.WriteString("\t},\n")
			}

			return nil
		}

		b.WriteString("\t{\n")
		b.WriteString(fmt.Sprintf("\t Name: \"%s\",\n", hashName))
		b.WriteString(fmt.Sprintf("\t Type: %d,\n", kernelType))
		b.WriteString(fmt.Sprintf("\t Category: \"%s\",\n", hashCategory))
		if example != "" {
			b.WriteString(fmt.Sprintf("\t Example: \"%s\",\n", example))
		}
		b.WriteString("\t},\n")

		return nil
	})

	b.WriteString("\t}\n\n")

	b.WriteString("// SupportedHashes returns a list of available hashes supported by Hashcat\n")
	b.WriteString("func SupportedHashes() []Hash {\n")
	b.WriteString("\t return hashes\n")
	b.WriteString("}\n")

	formattedSource, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatalf("Could not format generated source: %s", err)
	}

	fd, err := os.Create("./hash_types.go")
	if err != nil {
		log.Fatalf("Could not create destination file: %s", err)
	}
	defer fd.Close()

	if _, err := fd.Write(formattedSource); err != nil {
		log.Fatalf("Could not write destination file: %s", err)
	}
}
