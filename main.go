package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strconv"
	"strings"
)

var (
	err         error
	redactCount int
	removeCount int
)

func main() {
	var parsedValues string

	flag.IntVar(&redactCount, "redactCount", 65, "count how much from dorked files is shown")
	flag.IntVar(&removeCount, "removeCount", 5, "count after which fuzzing results will be cut off")
	// FOr testing
	//filePath := flag.String("file", "", "path to file with concated jsonl")
	flag.Parse()

	// Only for testing purposes
	//file, err := os.Open(*filePath)
	//if err != nil {
	//	log.Fatalf("could not open the file: %v", err)
	//}
	//defer file.Close()

	// Read big JSONL
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := read(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("error happened here: %v\n", err)
		}
		//rawJson = append(rawJson, line...)
		if strings.Contains(string(line[0:50]), "{\"commandline\":\"ffuf") {
			// Ffuf results
			parsedValues = parseFfufJson(line)

		} else if strings.Contains(string(line[0:50]), "{\"SourceMetadata\":") {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error getting current dir: "+err.Error())
			}
			// TruffleHog results
			parsedValues = parseTruffleHogJson(line)
		}
		if parsedValues != "" {
			fmt.Println(parsedValues)
		}
	}
}

func parseTruffleHogJson(values []byte) string {
	type Git struct {
		Commit     string `json:"commit"`
		File       string `json:"file"`
		Repository string `json:"repository"`
		Timestamp  string `json:"timestamp"`
		Line       int    `json:"line"`
	}
	type Data struct {
		Gitdata Git `json:"Git"`
	}
	type SourceMetadata struct {
		Dat Data `json:"Data"`
	}
	type TruffleHogResults struct {
		SM           SourceMetadata `json:"SourceMetadata"`
		DetectorType int            `json:"DetectorType"`
		Raw          string         `json:"Raw"`
	}
	var (
		ret    string
		result TruffleHogResults
	)

	json.Unmarshal(values, &result)

	if len(result.Raw) > redactCount {
		ret += strings.TrimSpace((result.Raw[:redactCount]) + " <redacted> | ")
	} else {
		ret += strings.TrimSpace((result.Raw) + " | ")
	}
	ret += strconv.Itoa(result.DetectorType) + " | "
	ret += result.SM.Dat.Gitdata.Timestamp + " | "
	ret += result.SM.Dat.Gitdata.Repository + " | "
	ret += result.SM.Dat.Gitdata.File + " | "
	ret += result.SM.Dat.Gitdata.Commit
	ret += "\n"

	return ret
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
