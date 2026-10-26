package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestReadmeChecklistBadge derives the displayed counts from the real, validated
// checklist, scanning the package directories CI's checklist step names. A
// stale numerator, denominator, alternative text or link fails CI.
func TestReadmeChecklistBadge(t *testing.T) {
	root := filepath.Join("..", "..")
	file := filepath.Join(root, "CHECKLIST.md")
	args := []string{"-file", file}
	for _, dir := range ciChecklistDirs(t) {
		args = append(args, filepath.Join(root, dir))
	}
	var out bytes.Buffer
	if code := run(args, &out, &out); code != 0 {
		t.Fatalf("checklist validation failed (exit %d):\n%s", code, out.String())
	}
	items, err := parseChecklist(file, func(format string, args ...any) {
		t.Errorf(format, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, it := range items {
		if !it.na {
			mapped++
		}
	}
	want := fmt.Sprintf("[![Checklist: %d/%d mapped](https://img.shields.io/badge/checklist-%d%%2F%d%%20mapped-blue)](CHECKLIST.md)",
		mapped, len(items), mapped, len(items))
	if !strings.Contains(readRepositoryFile(t, "README.md"), want) {
		t.Fatalf("stale or missing README checklist badge; want %s", want)
	}
}

func TestReadmeCoverageBadge(t *testing.T) {
	// This immutable producer's coverage_total rejects totals outside 95..100.
	// It has no configurable coverage threshold. Re-audit the gate when changing
	// the pin, then update this contract and the badge together if necessary.
	const auditedProducer = "rest-mail/go-spf/.github/workflows/rfc-verification.yml@7d291c08d310b9c62afc287e75a534a39150fafb"
	var workflow struct {
		Jobs map[string]struct {
			Uses string `yaml:"uses"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readRepositoryFile(t, ".github/workflows/ci.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	if got := workflow.Jobs["rfc"].Uses; got != auditedProducer {
		t.Fatalf("coverage gate needs re-audit: producer %q, audited %q", got, auditedProducer)
	}
	const want = "[![Coverage gate: ≥95%](https://img.shields.io/badge/coverage%20gate-%E2%89%A595%25-brightgreen)](COVERAGE.md)"
	if !strings.Contains(readRepositoryFile(t, "README.md"), want) {
		t.Fatalf("stale or missing README coverage badge; want %s", want)
	}
}

// ciChecklistDirs returns the package directories CI's RFC proof passes to
// the checklist command, so this test checks the same tests CI does.
func ciChecklistDirs(t *testing.T) []string {
	t.Helper()
	var workflow struct {
		Jobs map[string]struct {
			With map[string]string `yaml:"with"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readRepositoryFile(t, ".github/workflows/ci.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	var dirs []string
	if err := json.Unmarshal([]byte(workflow.Jobs["rfc"].With["checklist-dirs"]), &dirs); err != nil {
		t.Fatalf("CI checklist-dirs: %v", err)
	}
	if len(dirs) == 0 {
		t.Fatal("CI checklist-dirs names no package directory")
	}
	return dirs
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
