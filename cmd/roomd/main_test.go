package main

import (
	"testing"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
)

func TestParseSignals(t *testing.T) {
	got, err := parseSignals([]string{"SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != roomv1.SignalKind_SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT {
		t.Fatalf("signals = %v", got)
	}
}

func TestParseSignalsRejectsUnknownAndDuplicateNames(t *testing.T) {
	for name, input := range map[string][]string{
		"unknown":   {"SIGNAL_KIND_NOT_REAL"},
		"duplicate": {"SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT", "SIGNAL_KIND_RUST_UNSAFE_WITHOUT_SAFETY_CONTRACT"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSignals(input); err == nil {
				t.Fatal("expected invalid coverage to fail")
			}
		})
	}
}
