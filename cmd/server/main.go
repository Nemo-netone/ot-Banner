package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"banner-fingerprint/internal/fingerprint"
)

const defaultRules = "configs/fingerprints.json"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	addr := getenv("SERVER_ADDR", ":8080")
	rulesPath := getenv("RULES_FILE", defaultRules)
	maxBody := getenvInt("MAX_BODY_BYTES", 8*1024*1024)
	maxBatch := getenvInt("MAX_BATCH_SIZE", 1000)
	engine, err := fingerprint.LoadEngine(rulesPath)
	if err != nil {
		slog.Error("load fingerprint rules", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr: addr, Handler: routes(engine, maxBody, maxBatch),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		slog.Info("server listening", "addr", addr, "rules", rulesPath)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func routes(engine *fingerprint.Engine, maxBody, maxBatch int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
			writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxBody))
		decoder := json.NewDecoder(r.Body)
		var records []fingerprint.ScanRecord
		if err := decoder.Decode(&records); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON request")
			return
		}
		if len(records) > maxBatch {
			writeError(w, http.StatusRequestEntityTooLarge, "batch size exceeds limit")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeError(w, http.StatusBadRequest, "request must contain one JSON array")
			return
		}
		results := make([]fingerprint.FingerprintResult, len(records))
		for i, record := range records {
			results[i] = engine.Identify(record)
		}
		writeJSON(w, http.StatusOK, results)
	})
	return recoverMiddleware(mux)
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				slog.Error("request panic", "error", value)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func runHealthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := flags.String("url", "http://127.0.0.1:8080/health", "health URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health status: %s", response.Status)
	}
	return nil
}
func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func getenvInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
