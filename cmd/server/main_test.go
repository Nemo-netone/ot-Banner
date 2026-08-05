package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func TestFingerprintAPIValidation(t *testing.T) {
	engine, err := fingerprint.LoadEngine("../../configs/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	handler := routes(engine, 1024, 2)
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}] trailing`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got %d", response.Code)
	}
}
