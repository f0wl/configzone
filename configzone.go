// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └─────────────────────────────────┘

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ioReader is used to open the malware sample for parsing with debug/pe
func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// rc4decrypt decrypts the configuration data with the extracted key
func rc4decrypt(extkey []byte, data []byte) []byte {
	// create a new RC4 Enc/Dec Routine and pass the key
	cipher, ciphErr := rc4.NewCipher(extkey)
	check(ciphErr)
	// decrypt the config
	cipher.XORKeyStream(data, data)
	return data
}

// Flag variables for commandline arguments
var verboseFlag bool
var jsonFlag bool

// Structure to store extracted config information
type warzoneConfig struct {
	Host         string `json:"host"`
	Port         uint16 `json:"port"`
	Unknown1     string `json:"unknown1"`
	InstallName  string `json:"installName"`
	Unknown2     string `json:"unknown2"`
	RunKey       string `json:"runKey"`
	RetryDelay   int    `json:"retryDelay"`
	Capabilities string `json:"capabilities"`
	Random       string `json:"random"`
}

func main() {

	fmt.Printf("\n  ▄▄·        ▐ ▄ ·▄▄▄▪   ▄▄ • ·▄▄▄▄•       ▐ ▄ ▄▄▄ . \n")
	fmt.Printf("  ▐█ ▌▪▪     •█▌▐█▐▄▄·██ ▐█ ▀ ▪▪▀·.█▌▪     •█▌▐█▀▄.▀· \n")
	fmt.Printf("  ██ ▄▄ ▄█▀▄ ▐█▐▐▌██▪ ▐█·▄█ ▀█▄▄█▀▀▀• ▄█▀▄ ▐█▐▐▌▐▀▀▪▄ \n")
	fmt.Printf("  ▐███▌▐█▌.▐▌██▐█▌██▌.▐█▌▐█▄▪▐██▌▪▄█▀▐█▌.▐▌██▐█▌▐█▄▄▌ \n")
	fmt.Printf("  ·▀▀▀  ▀█▄▀▪▀▀ █▪▀▀▀ ▀▀▀·▀▀▀▀ ·▀▀▀ • ▀█▄▀▪▀▀ █▪ ▀▀▀  \n")
	fmt.Printf("  WarzoneRAT Configuration Extractor\n")
	fmt.Printf("  Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted config to a JSON file")
	flag.BoolVar(&verboseFlag, "v", false, "Verbose output")
	flag.Parse()

	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(flag.Args()[0])
	sha256sum := calcSHA256(flag.Args()[0])

	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ File size (bytes): \t", getFileInfo(flag.Args()[0]))
	fmt.Fprintln(w1, "→ Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ Sample SHA-256: \t", sha256sum)
	w1.Flush()

	// 	┌──────────────────────────────────────────────────────────────────────────────┐
	// │ Parsing the PE file, extracting the RC4 encrypted config and dectypting it   │
	// └──────────────────────────────────────────────────────────────────────────────┘

	// read the PE
	sample := ioReader(flag.Args()[0])

	f, parseErr := pe.NewFile(sample)
	check(parseErr)
	// dump out the contents of the .bss section
	sectionData, dumpErr := f.Section(".bss").Data()
	check(dumpErr)

	// trim the superfluous nullbytes from the end of the encrypted config
	encConfig := bytes.Trim(sectionData, "\x00")

	// retrieve the keysize, convert the bytes to an integer
	keySize := binary.LittleEndian.Uint32(encConfig[:4])
	// retrieve the RC4 key via the keysize
	extKey := encConfig[4 : 4+keySize]
	// decrypt the config
	plaintext := rc4decrypt(extKey, encConfig[4+keySize:])

	//=========================================================================

	if verboseFlag {
		color.Green("\n✓ Decrypted config hexdump:\n\n")
		fmt.Print(hex.Dump(plaintext))
	}

	// ┌──────────────────────────────────────────────────────────────────────┐
	// │ 	Extracting information from the decrypted configuration.         │
	// │ 	For more information about the structure of the configuration   │
	// │ 	check out the README (https://github.com/f0wl/configzone)      │
	// └──────────────────────────────────────────────────────────────────┘

	// I chose to use a counter var here to keep the slice offsets somewhat readable
	counter := 0
	// Initialize a new config struct
	var cfg warzoneConfig

	// C2 Hostname/IP --> 4 + x byte
	c2Size := int(binary.LittleEndian.Uint32(plaintext[:4]))
	counter += 4
	cfg.Host = string(plaintext[counter : counter+c2Size])
	counter += c2Size

	// C2 Port --> 2 byte
	cfg.Port = binary.LittleEndian.Uint16(plaintext[counter : counter+2])
	counter += 2

	// Unidentified (Config/Feature Options?) --> 7 byte
	cfg.Unknown1 = hex.EncodeToString(plaintext[counter : counter+7])
	counter += 7

	// Install name --> 4 + x byte
	installNameSize := int(binary.LittleEndian.Uint32(plaintext[counter : counter+4]))
	counter += 4
	cfg.InstallName = string(plaintext[counter : counter+installNameSize])
	counter += installNameSize

	// Unidentified (Switch) --> 1 byte
	cfg.Unknown2 = hex.EncodeToString(plaintext[counter : counter+1])
	counter += 1

	// Run Key (Registry Value) --> 4 + x byte
	runKeySize := int(binary.LittleEndian.Uint32(plaintext[counter : counter+4]))
	counter += 4
	cfg.RunKey = string(plaintext[counter : counter+runKeySize])
	counter += runKeySize

	// Unknown (more Feature Options?) --> something between 6 to 9 byte
	// the "undefined3" field can vary in length, so calculating the offset manually is the best option
	calcLength := len(plaintext) - 24
	cfg.RetryDelay = int(binary.LittleEndian.Uint32(plaintext[counter : counter+4]))
	cfg.Capabilities = hex.EncodeToString(plaintext[counter+4 : calcLength])
	counter += (calcLength - counter)

	// Random string --> 4 + 20 byte
	randomSize := int(binary.LittleEndian.Uint32(plaintext[counter : counter+4]))
	counter += 4
	cfg.Random = string(plaintext[counter : counter+randomSize])

	//=========================================================================

	color.Green("\n✓ Extracted configuration:\n\n")
	w2 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w2, "→ C2 Host: \t", cfg.Host)
	fmt.Fprintln(w2, "→ Port: \t", cfg.Port)
	fmt.Fprintln(w2, "→ Unknown 1: \t", cfg.Unknown1)
	fmt.Fprintln(w2, "→ Install name: \t", cfg.InstallName)
	fmt.Fprintln(w2, "→ Unknown 2: \t", cfg.Unknown2)
	fmt.Fprintln(w2, "→ Run Key (Startup name): \t", cfg.RunKey)
	fmt.Fprintln(w2, "→ Retry Delay: \t", cfg.RetryDelay)
	fmt.Fprintln(w2, "→ Password, Listening, RDP, Smartupdate, DownloadExec: \t", cfg.Capabilities)
	fmt.Fprintln(w2, "→ Random string: \t", cfg.Random)
	w2.Flush()

	// if configzone is run with -j the configuration will be written to disk in a JSON file
	if jsonFlag {

		// marshalling the config struct into a JSON string
		data, _ := json.Marshal(cfg)
		jsonString := string(data)
		// strip the unicode garbage
		jsonString = strings.ReplaceAll(jsonString, `\u0000`, "")

		filename := "config-" + md5sum + ".json"

		// write the JSON string to a file
		jsonOutput, writeErr := os.Create(filename)
		check(writeErr)
		defer f.Close()
		n3, err := jsonOutput.WriteString(jsonString)
		check(err)
		color.Green("\n✓ Wrote %d bytes to %v\n\n", n3, filename)
		jsonOutput.Sync()
	}

}
