package semgrepbundle

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validRule = `rules:
  - id: %s
    metadata:
      room_signal: SIGNAL_KIND_SECRET_LITERAL
      room_confidence_basis_points: 9000
    pattern: foo
`

func write(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBundleFilesDeterministicByID(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.yml", sprintf(validRule, "room.a"))
	b := write(t, dir, "b.yaml", sprintf(validRule, "room.b"))
	forward, err := BundleFiles([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := BundleFiles([]string{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if string(forward) != string(reverse) {
		t.Fatal("output depends on discovery order")
	}
	if !strings.HasPrefix(string(forward), warning+"rules:\n") || strings.Index(string(forward), "room.a") > strings.Index(string(forward), "room.b") {
		t.Fatalf("non-canonical output:\n%s", forward)
	}
}

func TestBundleRejectsInvalidFragments(t *testing.T) {
	tests := map[string][]string{
		"empty set":           {},
		"duplicate ids":       {sprintf(validRule, "room.same"), sprintf(validRule, "room.same")},
		"empty fragment":      {""},
		"malformed yaml":      {"rules: ["},
		"multiple documents":  {sprintf(validRule, "room.a") + "---\nrules: []\n"},
		"wrong shape":         {"other: []\n"},
		"multiple rules":      {sprintf(validRule, "room.a") + strings.TrimPrefix(sprintf(validRule, "room.b"), "rules:\n")},
		"missing id":          {"rules:\n  - metadata: {}\n"},
		"missing signal":      {"rules:\n  - id: room.a\n    metadata:\n      room_confidence_basis_points: 1\n"},
		"unknown signal":      {strings.ReplaceAll(sprintf(validRule, "room.a"), "SIGNAL_KIND_SECRET_LITERAL", "SIGNAL_KIND_NOPE")},
		"unspecified signal":  {strings.ReplaceAll(sprintf(validRule, "room.a"), "SIGNAL_KIND_SECRET_LITERAL", "SIGNAL_KIND_UNSPECIFIED")},
		"zero confidence":     {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", "0")},
		"high confidence":     {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", "10001")},
		"invalid confidence":  {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", "nope")},
		"float confidence":    {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", "9000.9")},
		"exponent confidence": {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", "1e3")},
		"quoted confidence":   {strings.ReplaceAll(sprintf(validRule, "room.a"), "9000", `"9000"`)},
		"duplicate id key": {strings.Replace(
			sprintf(validRule, "room.a"), "  - id: room.a\n", "  - id: room.a\n    id: room.b\n", 1,
		)},
		"duplicate metadata key": {strings.Replace(
			sprintf(validRule, "room.a"), "    metadata:\n", "    metadata: {}\n    metadata:\n", 1,
		)},
		"duplicate signal key": {strings.Replace(
			sprintf(validRule, "room.a"), "      room_signal: SIGNAL_KIND_SECRET_LITERAL\n", "      room_signal: SIGNAL_KIND_SECRET_LITERAL\n      room_signal: SIGNAL_KIND_SECRET_LITERAL\n", 1,
		)},
		"duplicate nested operator": {strings.Replace(
			sprintf(validRule, "room.a"), "    pattern: foo\n", "    patterns:\n      - pattern: foo\n        pattern: bar\n", 1,
		)},
		"anchor": {strings.Replace(
			sprintf(validRule, "room.a"), "    pattern: foo\n", "    pattern: &shared foo\n", 1,
		)},
		"alias": {strings.Replace(
			sprintf(validRule, "room.a"), "    pattern: foo\n", "    patterns:\n      - pattern: &shared foo\n      - pattern: *shared\n", 1,
		)},
		"merge key": {strings.Replace(
			sprintf(validRule, "room.a"), "    pattern: foo\n", "    pattern: foo\n    <<: {severity: ERROR}\n", 1,
		)},
	}
	for name, fragments := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var paths []string
			for i, fragment := range fragments {
				paths = append(paths, write(t, dir, sprintf("%d.yml", i), fragment))
			}
			if _, err := BundleFiles(paths); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBundleRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := write(t, dir, "rule.yml", sprintf(validRule, "room.a"))
	if err := os.Symlink(target, filepath.Join(dir, "linked.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Bundle(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestWriteFileDoesNotReplaceUnchangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "room.yml")
	data := []byte("same")
	if err := WriteFile(path, data); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if err := WriteFile(path, data); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged file was replaced")
	}
}

func TestWriteFileReplacesSymlinkWithoutChangingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yml")
	output := filepath.Join(dir, "room.yml")
	data := []byte("same")
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(output, data); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(output)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("output mode = %v, want regular file", info.Mode())
	}
	targetData, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(targetData, data) {
		t.Fatalf("target data = %q, want %q", targetData, data)
	}
}

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
