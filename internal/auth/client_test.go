package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClientTimesOutWaitingForResponseHeaders(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	client := NewHTTPClientWithTimeout("token", 25*time.Millisecond)
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("request unexpectedly waited without a response-header timeout")
	}
}
