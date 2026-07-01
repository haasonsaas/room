package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/store"
)

func TestDashboardRuleLifecycleAPI(t *testing.T) {
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	server := httptest.NewServer(New(app.New(ruleStore)))
	defer server.Close()

	body := `{"rule":{"id":"test-dashboard-rule","title":"Dashboard rule","description":"Created from API","severity":4,"enabled":true,"checks":[{"kind":1,"expression":"always"}]}}`
	resp, err := http.Post(server.URL+"/api/rules", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want 200", resp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/rules/test-dashboard-rule", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", resp.StatusCode)
	}
}
