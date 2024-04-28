package parser

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/m-1tZ/pfjson/pkg/generic"
	log "github.com/sirupsen/logrus"
)

// {"SourceMetadata":{"Data":{"Filesystem":{"file":"/pwd/new_key","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":false,"Raw":"AKIAQYLPMN5HHHFPZAM2","RawV2":"AKIAQYLPMN5HHHFPZAM21tUm636uS1yOEcfP5pvfqJ/ml36mF7AkyHsEU0IU","Redacted":"AKIAQYLPMN5HHHFPZAM2","ExtraData":{"account":"052310077262","resource_type":"Access key"},"StructuredData":null}

func ParseTruffleHogFilesystemJSON(values []byte, redactCount int) string {
	type Filesystem struct {
		File string `json:"file"`
		Line int    `json:"line"`
	}
	type Data struct {
		Filesystemdata Filesystem `json:"Filesystem"`
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

	if len(result.Raw) > redactCount {
		ret += strings.Replace(strings.TrimSpace((result.Raw[:redactCount]))+" <redacted> | ", "\n", "", -1)
	} else {
		ret += strings.Replace(strings.TrimSpace((result.Raw))+" | ", "\n", "", -1)
	}
	ret += result.SM.Dat.Filesystemdata.File + " | "
	ret += result.DetectorName + " | "
	ret += " " + strconv.Itoa(result.SM.Dat.Filesystemdata.Line)
	return ret
}

//{"SourceMetadata":{"Data":{"Postman":{"link":"https://go.postman.co/request/26596579-8627d75c-a9d7-40cd-b755-25f12aac74cb?tab=auth","workspace_uuid":"80818d3f-10ca-4b75-9258-ee3e8f6c8d77","workspace_name":"Tredence Inc","collection_id":"26596579-76acd76d-62b0-4626-bc51-a6145a9735ed","collection_name":"GitHubUsingVariable","environment_id":"26596579-7e39a493-95e4-43b2-9c39-ce0c4606db61","request_id":"8627d75c-a9d7-40cd-b755-25f12aac74cb","request_name":"createRepo","folder_id":"8627d75c-a9d7-40cd-b755-25f12aac74cb","folder_name":"createRepo","field_type":"request\u003e request auth \u003e authorization"}}},"SourceID":1,"SourceType":33,"SourceName":"trufflehog - postman","DetectorType":8,"DetectorName":"Github","DecoderName":"PLAIN","Verified":false,"Raw":"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","RawV2":"","Redacted":"","ExtraData":{"rotation_guide":"https://howtorotate.com/docs/tutorials/github/","version":"2"},"StructuredData":null}

func ParseTruffleHogPostmanJSON(values []byte, redactCount int) string {
	type Postman struct {
		Link          string `json:"link"`
		WorkspaceName string `json:"workspace_name"`
		WorkspaceUUID string `json:"workspace_uuid"`
		FieldType     string `json:"field_type"`
	}
	type Data struct {
		Postman Postman `json:"Postman"`
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

	if len(result.Raw) > redactCount {
		ret += strings.Replace(strings.TrimSpace((result.Raw[:redactCount]))+" <redacted> | ", "\n", "", -1)
	} else {
		ret += strings.Replace(strings.TrimSpace((result.Raw))+" | ", "\n", "", -1)
	}
	ret += result.SM.Dat.Postman.Link + " | "
	ret += result.DetectorName + " | "
	ret += result.SM.Dat.Postman.WorkspaceName + " | "
	ret += " " + result.SM.Dat.Postman.FieldType

	return ret
}

// {"SourceMetadata":{"Data":{"Github":{"link":"https://github.com/allegro/ralph/issues/2298#issuecomment-299789367","username":"roteme13","repository":"ralph","timestamp":"2017-05-08 07:05:14 +0000 UTC"}}},"SourceID":1,"SourceType":7,"SourceName":"trufflehog - github","DetectorType":901,"DetectorName":"LDAP","DecoderName":"PLAIN","Verified":false,"Raw":"ldap://dc.com:389\tgivenName\t1234567","RawV2":"","Redacted":"","ExtraData":null,"StructuredData":null}

func ParseTruffleHogGithubJSON(values []byte, redactCount int) string {
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

	if len(result.Raw) > redactCount {
		ret += strings.Replace(strings.TrimSpace((result.Raw[:redactCount]))+" <redacted> | ", "\n", "", -1)
	} else {
		ret += strings.Replace(strings.TrimSpace((result.Raw))+" | ", "\n", "", -1)
	}
	ret += result.SM.Dat.Gitdata.Link + " | "
	ret += result.DetectorName + " | "
	ret += " " + strconv.Itoa(result.SM.Dat.Gitdata.Line)

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
			ret += strconv.Itoa(item.Status) + " "
			ret += strconv.Itoa(item.Length) + " "
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
