package generic

import (
	"bufio"
	"bytes"
	"net/url"
	"strings"
)

func RemoveEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" && str != " " {
			r = append(r, str)
		}
	}
	return r
}

func BlobToSlice(blob []byte) ([]byte, error) {
	var index int
	// seems like already patched
	if bytes.HasPrefix(blob, []byte("[")) && bytes.HasSuffix(blob, []byte("]")) {
		return blob, nil
	}

	// closing slice tag
	blob = append(blob, ']')

	// opening slice tag
	blob = append([]byte("["), blob...)

	// include , between ffuf json results
	// }},{"commandline":"
	for {
		index = bytes.Index(blob, []byte("}}{\"commandline\":\""))
		if index < 0 {
			break
		}
		blob = insertAtPos(blob, index+2, byte(','))
	}
	//index := bytes.IndexAny(blob, "}}{\"commandline\":\"")

	return blob, nil
}

func AddDelimiterToSlice(slice []string) ([]string, error) {
	// 403 112 https://asdf.com
	var newSlice []string
	for key, item := range slice {
		if key == 0 {
			newSlice = append(newSlice, item)
			continue
		}

		before := strings.Split(slice[key-1], " ")[2]
		current := strings.Split(slice[key], " ")[2]

		urlBefore, err := url.Parse(before)
		if err != nil {
			return []string{}, err
		}

		urlCurrent, err := url.Parse(current)
		if err != nil {
			return []string{}, err
		}

		if urlBefore.Hostname() != urlCurrent.Hostname() {
			newSlice = append(newSlice, "---")
		}
		newSlice = append(newSlice, item)
	}
	return newSlice, nil
}

func insertAtPos(a []byte, index int, value byte) []byte {
	if len(a) == index { // nil or empty slice or after last element
		return append(a, value)
	}
	a = append(a[:index+1], a[index:]...) // index < len(a)
	a[index] = value
	return a
}

func Read(r *bufio.Reader) ([]byte, error) {
	var (
		isPrefix = true
		err      error
		line, ln []byte
	)

	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}

	return ln, err
}
