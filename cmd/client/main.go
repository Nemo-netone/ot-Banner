package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"banner-fingerprint/internal/fingerprint"
)

func main() {
	file := flag.String("file", "", "input JSON file")
	server := flag.String("server", "http://localhost:8080", "server URL")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()
	if *file == "" {
		fatal("--file is required")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fatal("read input: %v", err)
	}
	var records []fingerprint.ScanRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&records); err != nil {
		fatal("invalid input JSON: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		fatal("input must contain one JSON array")
	}
	body, err := json.Marshal(records)
	if err != nil {
		fatal("encode input: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, *server+"/fingerprint", bytes.NewReader(body))
	if err != nil {
		fatal("create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: *timeout}).Do(request)
	if err != nil {
		fatal("request server: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4*1024))
		fatal("server returned %s: %s", response.Status, bytes.TrimSpace(message))
	}
	var results []fingerprint.FingerprintResult
	if err := json.NewDecoder(response.Body).Decode(&results); err != nil {
		fatal("decode response: %v", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fatal("write output: %v", err)
	}
}

func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
