package generic

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

func FilterFuzzed(fuzzResults string, removeCount int) []string {
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
		// line "403 13 http://bestivalvr.redbull.com/HTTPClntRecv/*"
		// remove "  " possible empty slice fields
		items = RemoveEmpty(strings.Split(line, " "))
		if len(items) != 3 {
			log.Error("Substring ' ' occurrs not exactly 2 times in " + line)
			continue
		}
		// 403 13
		item = items[0] + " " + items[1]
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
		item = items[0] + " " + items[1]
		// if entry exist and if entry count is higher than remove_count, omit
		if _, found := toRemove[item]; found && removeCount > toRemove[item] {
			filteredResults = append(filteredResults, line)
		}
	}

	return filteredResults
}
