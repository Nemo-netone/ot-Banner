package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

type ScanRecord struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

type FingerprintResult struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

func main() {
	file := flag.String("file", "", "input JSON file")
	server := flag.String("server", "http://localhost:8080", "server URL")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	flag.Parse()

	if *file == "" {
		fmt.Println("Usage: client --file input.json --server http://server:8080")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Printf("read file: %v\n", err)
		os.Exit(1)
	}

	var records []ScanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		fmt.Printf("unmarshal: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: *timeout}
	url := *server + "/fingerprint"

	body, err := json.Marshal(records)
	if err != nil {
		fmt.Printf("marshal: %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("new request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var results []FingerprintResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		fmt.Printf("decode: %v\n", err)
		os.Exit(1)
	}

	json.NewEncoder(os.Stdout).Encode(results)
}
