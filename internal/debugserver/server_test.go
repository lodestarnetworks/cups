package debugserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRejectsNonLoopbackListener(t *testing.T) {
	for _, address := range []string{"0.0.0.0:6060", "10.0.0.1:6060", "127.0.0.1:0", "invalid"} {
		if _, err := New(address); err == nil {
			t.Fatalf("accepted debug address %q", address)
		}
	}
	if _, err := New("127.0.0.1:6060"); err != nil {
		t.Fatal(err)
	}
}

func TestPprofIndexIsRegistered(t *testing.T) {
	server, err := New("127.0.0.1:6060")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "profile") {
		t.Fatalf("pprof response = %d %q", response.Code, response.Body.String())
	}
}
