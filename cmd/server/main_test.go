package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func testHandler(t *testing.T, maxBody, maxBatch int) http.Handler {
	t.Helper()
	engine, err := fingerprint.LoadEngine("../../configs/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return routes(engine, maxBody, maxBatch)
}

func request(handler http.Handler, path, method, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestAPIValidation(t *testing.T) {
	handler := testHandler(t, 1024, 2)
	tests := []struct {
		name, path, method, contentType, body string
		status                                int
	}{
		{"health", "/health", http.MethodGet, "", "", http.StatusOK},
		{"wrong method", "/fingerprint", http.MethodGet, "application/json", "[]", http.StatusMethodNotAllowed},
		{"missing content type", "/fingerprint", http.MethodPost, "", "[]", http.StatusUnsupportedMediaType},
		{"wrong content type", "/fingerprint", http.MethodPost, "text/plain", "[]", http.StatusUnsupportedMediaType},
		{"invalid json", "/fingerprint", http.MethodPost, "application/json", "[", http.StatusBadRequest},
		{"trailing data", "/fingerprint", http.MethodPost, "application/json", "[] trailing", http.StatusBadRequest},
		{"batch too large", "/fingerprint", http.MethodPost, "application/json", `[{"banner":"a"},{"banner":"b"},{"banner":"c"}]`, http.StatusRequestEntityTooLarge},
		{"empty array", "/fingerprint", http.MethodPost, "application/json", "[]", http.StatusOK},
		{"unknown succeeds", "/fingerprint", http.MethodPost, "application/json", `[{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}]`, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(handler, test.path, test.method, test.contentType, test.body)
			if response.Code != test.status {
				t.Fatalf("got status %d, body %s", response.Code, response.Body.String())
			}
		})
	}

	largeHandler := testHandler(t, 32, 2)
	response := request(largeHandler, "/fingerprint", http.MethodPost, "application/json", `[{"banner":"012345678901234567890123456789012345"}]`)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body got status %d, body %s", response.Code, response.Body.String())
	}
}
