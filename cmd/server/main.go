package main

import (
	"encoding/json"
	"log"
	"net/http"
	"banner-fingerprint/internal/fingerprint"
)

func main() {
	e := fingerprint.NewEngine()

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/fingerprint", fingerprintHandler(e))
	http.HandleFunc("/healthcheck", healthCheckHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func fingerprintHandler(e *fingerprint.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var records []fingerprint.ScanRecord
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		results := make([]fingerprint.FingerprintResult, len(records))
		for i, record := range records {
			results[i] = e.Identify(record)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	}
}
