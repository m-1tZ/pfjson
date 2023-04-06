package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/m-1tZ/pfjson/pkg/generic"
	"github.com/m-1tZ/pfjson/pkg/parser"
	log "github.com/sirupsen/logrus"
)

var (
	err         error
	redactCount int
	removeCount int
)

func main() {
	var parsedValues string

	log.SetLevel(log.ErrorLevel) //ErrorLevel, DebugLevel

	flag.IntVar(&redactCount, "redactCount", 65, "count how much from trufflehog dorked files is shown")
	flag.IntVar(&removeCount, "removeCount", 5, "count after which ffuf results will be cut off")
	// For testing
	//filePath := flag.String("file", "", "path to file with concated jsonl")
	flag.Parse()

	// Only for testing purposes
	// file, err := os.Open(*filePath)
	// if err != nil {
	// 	log.Fatalf("could not open the file: %v", err)
	// }
	// defer file.Close()

	// Read big JSONL
	reader := bufio.NewReader(os.Stdin) //os.Stdin or file for testing
	for {
		line, err := generic.Read(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("error happened here: %v\n", err)
		}
		//rawJson = append(rawJson, line...)
		if strings.Contains(string(line[0:50]), "{\"commandline\":\"") {
			// Ffuf results
			parsedValues = parser.ParseFfufJSON(line, removeCount)

		} else if strings.Contains(string(line[0:50]), "{\"SourceMetadata\":{\"Data\":{\"") {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting current dir: "+err.Error())
			}
			// TruffleHog results
			parsedValues = parser.ParseTruffleHogJSON(line, redactCount)
		} else {
			fmt.Println("[-] No supported input type was found (supported: trufflehog-dork, ffuf)")
		}
		if parsedValues != "" {
			fmt.Println(parsedValues)
		}
	}
}
