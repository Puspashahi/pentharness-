package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

type record struct {
	Method string          `json:"method"`
	URL    string          `json:"url"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

type observation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Hash   string `json:"bodyHash"`
}

type fileResult struct {
	File         string        `json:"file"`
	Rows         int           `json:"rows"`
	Invalid      int           `json:"invalid"`
	Observations []observation `json:"observations"`
	Errors       []string      `json:"errors,omitempty"`
}

type report struct {
	Tool              string       `json:"tool"`
	Safety            string       `json:"safety"`
	Files             int          `json:"files"`
	Rows              int          `json:"rows"`
	Invalid           int          `json:"invalid"`
	DuplicateEvidence int          `json:"duplicateEvidence"`
	Results           []fileResult `json:"results"`
}

func bodyHash(body json.RawMessage) string {
	var value interface{}
	if json.Unmarshal(body, &value) == nil {
		if canonical, err := json.Marshal(value); err == nil {
			body = canonical
		}
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func processFile(filename string) fileResult {
	result := fileResult{File: filename}
	file, err := os.Open(filename)
	if err != nil {
		result.Errors = []string{err.Error()}
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 8*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var item record
		if err := json.Unmarshal([]byte(raw), &item); err != nil || item.URL == "" {
			result.Invalid++
			continue
		}
		result.Rows++
		result.Observations = append(result.Observations, observation{
			File: filename, Line: line, Method: strings.ToUpper(item.Method),
			URL: item.URL, Status: item.Status, Hash: bodyHash(item.Body),
		})
	}
	if err := scanner.Err(); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	return result
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pentharness-evidence CAPTURE.jsonl [CAPTURE.jsonl ...]")
		os.Exit(2)
	}
	results := make([]fileResult, len(os.Args)-1)
	var wg sync.WaitGroup
	for i, filename := range os.Args[1:] {
		wg.Add(1)
		go func(index int, name string) {
			defer wg.Done()
			results[index] = processFile(name)
		}(i, filename)
	}
	wg.Wait()

	seen := map[string]bool{}
	totalRows, totalInvalid, duplicates := 0, 0, 0
	for _, result := range results {
		totalRows += result.Rows
		totalInvalid += result.Invalid
		for _, item := range result.Observations {
			key := item.Method + "\x00" + item.URL + "\x00" + fmt.Sprint(item.Status) + "\x00" + item.Hash
			if seen[key] {
				duplicates++
			}
			seen[key] = true
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].File < results[j].File })
	output := report{
		Tool:   "pentharness-go-evidence",
		Safety: "passive JSONL validation and hashing; no network requests; not a vulnerability detector",
		Files:  len(results), Rows: totalRows, Invalid: totalInvalid,
		DuplicateEvidence: duplicates, Results: results,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
