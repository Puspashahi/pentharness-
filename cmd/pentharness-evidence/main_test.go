package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessFileValidatesAndHashes(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "capture.jsonl")
	if err := os.WriteFile(file, []byte(
		"{\"method\":\"get\",\"url\":\"https://api.test/me\",\"status\":200,\"body\":{\"id\":1}}\n"+
			"not-json\n"+
			"{\"url\":\"https://api.test/me\",\"status\":200,\"body\":{\"id\":1}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := processFile(file)
	if result.Rows != 2 || result.Invalid != 1 {
		t.Fatalf("unexpected counts: rows=%d invalid=%d", result.Rows, result.Invalid)
	}
	if result.Observations[0].Hash == "" || result.Observations[0].Hash != result.Observations[1].Hash {
		t.Fatal("canonical JSON bodies should produce the same hash")
	}
}
