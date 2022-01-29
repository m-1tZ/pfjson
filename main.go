package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	pathP "path"
	"strconv"
	"strings"
)

func main() {
	var (
		jsonString   string
		parsedValues string
		targetPath   string
		err          error
	)
	rawJson := make([]string, 0)

	ns := bufio.NewScanner(os.Stdin)
	for ns.Scan() {
		rawJson = append(rawJson, ns.Text())
		ns.Bytes()
	}

	jsonString = strings.Join(rawJson, "")

	// Somehow detect if trufflehog or fuzz json
	if strings.Contains(jsonString, "{\"commandline\":\"ffuf") {
		// Ffuf results
		parsedValues = ParseFfufJson([]byte(jsonString))

	} else if strings.Contains(jsonString, "{\"branch\":") {
		targetPath, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting current dir: "+err.Error())
		}
		// TruffleHog results
		parsedValues = ParseTruffleHogJson([]byte(jsonString), targetPath)
	}

	fmt.Println(parsedValues)

	//go func() {
	//	ns := bufio.NewScanner(os.Stdin)
	//	for ns.Scan() {
	//		// Make sure that there are no duplicate parameter values
	//		rawJsonQueue <- ns.Text()
	//	}
	//	close(rawJsonQueue)
	//	return
	//}()
}

func ParseFfufJson(values []byte) string {
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
	)
	json.Unmarshal(values, &results)
	for _, result := range results.Results {
		ret += result.Url + " "
		ret += strconv.Itoa(result.Status) + " "
		ret += strconv.Itoa(result.Words) + "\n"
	}
	return ret
}

func ParseTruffleHogJson(values []byte, p string) string {
	type TruffleHogResults struct {
		Branch     string `json:"branch"`
		Date       string `json:"date"`
		Path       string `json:"path"`
		CommitHash string `json:"commitHash"`
		PrintDiff  string `json:"printDiff"`
		//Reason       string   `json:"reason"`
		StringsFound []string `json:"stringsFound"`
	}
	var ret string
	results := make([]TruffleHogResults, 0)
	json.Unmarshal(values, &results)

	for _, result := range results {
		ret += result.PrintDiff + " | "
		ret += result.Branch + " | "
		ret += result.CommitHash + " | "
		ret += result.Date + " | "
		ret += pathP.Base(p) + "/" + result.Path + " | "
		for _, str := range result.StringsFound {
			if len(str) > 65 {
				ret += strings.TrimSpace(str[:65]) + " <redacted> | "
			} else {
				ret += strings.TrimSpace(str) + " | "
			}
		}
		ret += "\n"
	}
	return ret
}

func filterFuzzed(path string) ([]string, error) {
	var (
		jsonFile        *os.File
		byteValue       []byte
		toRemove        = make(map[string]int)
		item            string
		items           []string
		parsedJson      string
		splittedJson    []string
		filteredResults []string
	)
	if jsonFile, err = os.Open(path); err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	byteValue, _ = ioutil.ReadAll(jsonFile)
	parsedJson = ParseFfufJson(byteValue)
	splittedJson = strings.Split(parsedJson, "\n")

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
		if _, found := toRemove[item]; found && Config.Values.RemoveCount > toRemove[item] {
			filteredResults = append(filteredResults, line)
		}
	}
	return filteredResults, err
}

func RemoveEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" && str != " " {
			r = append(r, str)
		}
	}
	return r
}
