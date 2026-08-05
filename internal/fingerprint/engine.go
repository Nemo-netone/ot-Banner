package fingerprint

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
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

type Engine struct {
	rules map[string]float64
}

func NewEngine() *Engine {
	e := &Engine{
		rules: make(map[string]float64),
	}
	// Simple rules for demo
	e.rules["SSH-2.0-OpenSSH"] = 0.95
	e.rules["Server: nginx"] = 0.90
	e.rules["Server: Apache"] = 0.90
	e.rules["Server: Jetty"] = 0.85
	e.rules["J\\x00"] = 0.90 // for MySQL
	e.rules["-ERR"] = 0.80
	e.rules["\\+PONG"] = 0.80
	e.rules["220 ProFTPD"] = 0.90
	return e
}

func (e *Engine) Identify(record ScanRecord) FingerprintResult {
	banner := strings.ToLower(record.Banner)
	result := FingerprintResult{
		IP:         record.IP,
		Port:       record.Port,
		Protocol:   "unknown",
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}

	// Match logic
	if strings.Contains(banner, "ssh-2.0-openssh") {
		result.Protocol = "SSH"
		result.Product = "OpenSSH"
		result.Confidence = 0.95
		if strings.Contains(banner, "ubuntu") {
			result.OSHint = "Ubuntu"
		}
	} else if strings.Contains(banner, "server: nginx") {
		result.Protocol = "HTTP"
		result.Product = "nginx"
		result.Confidence = 0.90
	} else if strings.Contains(banner, "server: apache") {
		result.Protocol = "HTTP"
		result.Product = "Apache"
		result.Confidence = 0.90
	} else if strings.Contains(banner, "server: jetty") {
		result.Protocol = "HTTP"
		result.Product = "Jetty"
		result.Confidence = 0.85
	} else if strings.Contains(banner, "j\\x00") || strings.Contains(banner, "mysql") {
		result.Protocol = "MySQL"
		result.Product = "MySQL"
		result.Confidence = 0.90
	} else if strings.Contains(banner, "-err") {
		result.Protocol = "Redis"
		result.Product = "Redis"
		result.Confidence = 0.80
	} else if strings.Contains(banner, "+pong") {
		result.Protocol = "Redis"
		result.Product = "Redis"
		result.Confidence = 0.80
	} else if strings.Contains(banner, "220 proftpd") {
		result.Protocol = "FTP"
		result.Product = "ProFTPD"
		result.Confidence = 0.90
	}

	return result
}
