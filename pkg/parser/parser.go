package parser

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/m-1tZ/pfjson/pkg/generic"
	log "github.com/sirupsen/logrus"
)

func ParseTruffleHogJSON(values []byte, redactCount int) string {
	type Github struct {
		Link      string `json:"link"`
		Timestamp string `json:"timestamp"`
		Line      int    `json:"line"`
	}
	type Data struct {
		Gitdata Github `json:"Github"`
	}
	type SourceMetadata struct {
		Dat Data `json:"Data"`
	}
	type TruffleHogResults struct {
		SM           SourceMetadata `json:"SourceMetadata"`
		DetectorName string         `json:"DetectorName"`
		Raw          string         `json:"Raw"`
	}
	var (
		ret    string
		result TruffleHogResults
	)

	json.Unmarshal(values, &result)

	ret += result.DetectorName + " | "
	ret += result.SM.Dat.Gitdata.Link + " | "
	if len(result.Raw) > redactCount {
		ret += strings.TrimSpace((result.Raw[:redactCount]) + " <redacted> | ")
	} else {
		ret += strings.TrimSpace((result.Raw) + " | ")
	}
	//ret += result.SM.Dat.Gitdata.Timestamp + " | "
	ret += strconv.Itoa(result.SM.Dat.Gitdata.Line)
	ret += "\n"

	return ret
}

func ParseFfufJSON(values []byte, removeCount int) string {
	// Inner of ffuf json: results:[...]
	type FfufInner struct {
		Url    string `json:"url"`
		Status int    `json:"status"`
		Length int    `json:"length"`
	}
	// Outer of ffuf json: {commandline:x,time:x,results[...]}
	type FfufResults struct {
		Results []FfufInner `json:"results"`
	}

	var (
		// Multiple ffuf jsons in one file
		results []FfufResults
		ret     string
		retList []string
	)

	// Patch file from {ffuf_result}{ffuf_result2} to [{ffuf_result},{ffuf_result2}]
	values, err := generic.BlobToSlice(values)
	if err != nil {
		log.Fatalf("Error during patching: %v", err.Error())
	}

	// unmarshal each object by its own
	json.Unmarshal(values, &results)

	for _, result := range results {
		for _, item := range result.Results {
			ret += strconv.Itoa(item.Length) + " "
			ret += strconv.Itoa(item.Status) + " "
			ret += item.Url + "\n"
		}
	}

	retList = generic.FilterFuzzed(ret, removeCount)

	// remove empty lines
	//retList = generic.RemoveEmpty(retList)

	// attach delimiter for host separation
	retList, err = generic.AddDelimiterToSlice(retList)
	if err != nil {
		log.Fatal("Error AddDelimiterToSlice: %v", err.Error())
	}

	return strings.Join(retList, "\n")
}
