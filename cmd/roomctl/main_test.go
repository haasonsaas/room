package main

import "testing"

func TestHookFilePathsIncludesToolInputFilePath(t *testing.T) {
	paths := hookFilePaths(map[string]any{
		"tool_input": map[string]any{
			"file_path": "src/api.rs",
		},
	})

	if len(paths) != 1 || paths[0] != "src/api.rs" {
		t.Fatalf("paths = %v, want [src/api.rs]", paths)
	}
}

func TestUniqueNonEmptyDeduplicatesHookFiles(t *testing.T) {
	got := uniqueNonEmpty([]string{"src/api.rs", "", " src/api.rs ", "src/lib.rs"})
	want := []string{"src/api.rs", "src/lib.rs"}
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths = %v, want %v", got, want)
		}
	}
}
