package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	pathP "path"
	"strconv"
	"strings"
)

var (
	err error
)

const (
	removeCount = 6
	redactCount = 65
)

func main() {
	var (
		targetPath   string
		parsedValues string
		rawJson      []byte
	)
	filePath := flag.String("file", "", "path to file with concated jsonl")
	flag.Parse()

	// Only for testing purposes
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("could not open the file: %v", err)
	}
	defer file.Close()

	// Read big JSONL
	reader := bufio.NewReader(file) //os.Stdin
	for {
		line, err := read(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("error happened here: %v\n", err)
		}
		rawJson = append(rawJson, line...)
	}

	if strings.Contains(string(rawJson[0:50]), "{\"commandline\":\"ffuf") {
		// Ffuf results
		parsedValues = parseFfufJson(rawJson)

	} else if strings.Contains(string(rawJson[0:50]), "{\"branch\":") {
		targetPath, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting current dir: "+err.Error())
		}
		// TruffleHog results
		parsedValues = parseTruffleHogJson(rawJson, targetPath)
	}
	fmt.Println(parsedValues)
	fmt.Println("version1.12")
}

func parseFfufJson(values []byte) string {
	type FfufResult struct {
		Url    string `json:"url"`
		Status int    `json:"status"`
		Words  int    `json:"words"`
	}
	type FfufResults struct {
		Results []FfufResult `json:"results"`
	}
	var (
		results FfufResults
		ret     string
		retList []string
	)
	json.Unmarshal(values, &results)
	for _, result := range results.Results {
		ret += result.Url + " "
		ret += strconv.Itoa(result.Status) + " "
		ret += strconv.Itoa(result.Words) + "\n"
	}

	retList = filterFuzzed(ret)

	// remove empty lines
	retList = RemoveEmpty(retList)

	return strings.Join(retList, "\n")
}

func parseTruffleHogJson(values []byte, p string) string {
	type TruffleHogResults struct {
		Branch     string `json:"branch"`
		Date       string `json:"date"`
		Path       string `json:"path"`
		CommitHash string `json:"commitHash"`
		PrintDiff  string `json:"printDiff"`
		//Reason       string   `json:"reason"`
		StringsFound []string `json:"stringsFound"`
	}
	var (
		ret            string
		splittedDorked []string
	)
	results := make([]TruffleHogResults, 0)
	json.Unmarshal(values, &results)

	for _, result := range results {
		ret += result.PrintDiff + " | "
		ret += result.Branch + " | "
		ret += result.CommitHash + " | "
		ret += result.Date + " | "
		ret += pathP.Base(p) + "/" + result.Path + " | "
		for _, str := range result.StringsFound {
			if len(str) > redactCount {
				ret += strings.TrimSpace(str[:redactCount]) + " <redacted> | "
			} else {
				ret += strings.TrimSpace(str) + " | "
			}
		}
		ret += "\n"
	}

	splittedDorked = strings.Split(ret, "\n")

	// remove empty lines
	splittedDorked = RemoveEmpty(splittedDorked)

	return strings.Join(splittedDorked, "\n")
}

func filterFuzzed(fuzzResults string) []string {
	var (
		toRemove        = make(map[string]int)
		item            string
		items           []string
		splittedJson    []string
		filteredResults []string
	)
	splittedJson = strings.Split(fuzzResults, "\n")

	// remove empty lines
	splittedJson = RemoveEmpty(splittedJson)

	// handle indexOutOfRange
	defer func() {
		if err := recover(); err != nil {
			log.Fatal(err)
		}
	}()

	for _, line := range splittedJson {
		// line "http://bestivalvr.redbull.com/HTTPClntRecv/* 403 13"
		// remove "  " possible empty slice fields
		items = RemoveEmpty(strings.Split(line, " "))
		if len(items) != 3 {
			log.Error("Substring ' ' occurrs not exactly 2 times in " + line)
			continue
		}
		// 403 13
		item = items[1] + " " + items[2]
		// check if 403 13 already occurs, if so then update counter
		if _, found := toRemove[item]; found {
			toRemove[item]++
		} else {
			toRemove[item] = 0
		}
	}
	// sight similar responses
	for _, line := range splittedJson {
		// remove "  " possible empty slice fields
		items = RemoveEmpty(strings.Split(line, " "))
		if len(items) != 3 {
			log.Error("Substring ' ' occurrs not exactly 2 times in " + line)
			continue
		}
		// 403 13
		item = items[1] + " " + items[2]
		// if entry exist and if entry count is higher than remove_count, omit
		if _, found := toRemove[item]; found && removeCount > toRemove[item] {
			filteredResults = append(filteredResults, line)
		}
	}
	return filteredResults
}
