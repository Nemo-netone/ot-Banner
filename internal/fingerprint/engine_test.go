package fingerprint

import "testing"

func TestEngineIdentifyAcceptanceSamples(t *testing.T) {
	engine, err := LoadEngine("../../configs/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, banner, protocol, product, version, os string
		port                                         int
	}{
		{"ssh ubuntu", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH", "OpenSSH", "8.9p1", "Ubuntu", 22},
		{"ssh debian", "SSH-2.0-OpenSSH_9.3 Debian-1", "SSH", "OpenSSH", "9.3", "Debian", 22},
		{"ssh 1.99", "SSH-1.99-OpenSSH_4.3", "SSH", "OpenSSH", "4.3", "", 22},
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", "HTTP", "nginx", "1.24.0", "", 80},
		{"apache", "HTTP/1.1 200 OK\r\nserver: Apache/2.4.57 (Ubuntu)", "HTTP", "Apache", "2.4.57", "Ubuntu", 443},
		{"jetty", "HTTP/1.1 404\r\nServer: Jetty/9.4.51", "HTTP", "Jetty", "9.4.51", "", 8080},
		{"iis", "HTTP/1.1 200\r\nServer: Microsoft-IIS/10.0", "HTTP", "Microsoft-IIS", "10.0", "", 8888},
		{"mysql 8", "J\x00\x00\x00\n8.0.32\x00", "MySQL", "MySQL", "8.0.32", "", 3306},
		{"mysql 5", "J\x00\x00\x00\n5.7.42\x00", "MySQL", "MySQL", "5.7.42", "", 3306},
		{"redis pong", "+PONG", "Redis", "Redis", "", "", 6379},
		{"redis error", "-ERR wrong number of arguments", "Redis", "Redis", "", "", 6379},
		{"redis noauth", "-NOAUTH Authentication required.", "Redis", "Redis", "", "", 6379},
		{"proftpd", "220 ProFTPD 1.3.7 Server", "FTP", "ProFTPD", "1.3.7", "", 21},
		{"vsftpd", "220 (vsFTPd 3.0.5)", "FTP", "vsFTPd", "3.0.5", "", 21},
		{"pureftpd", "220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", "", 21},
		{"tls", "\\x16\\x03\\x01\\x00\\xa5", "TLS", "", "", "", 9999},
		{"unknown", "QUIT\r\n", "unknown", "", "", "", 12345},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := engine.Identify(ScanRecord{IP: "127.0.0.1", Port: test.port, Banner: test.banner})
			if result.Protocol != test.protocol || result.Product != test.product || result.Version != test.version || result.OSHint != test.os {
				t.Fatalf("got %+v", result)
			}
		})
	}
}

func TestEngineBinaryInputsAndLimits(t *testing.T) {
	engine, err := LoadEngine("../../configs/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Identify(ScanRecord{Port: 9999, BannerBase64: "FgMBAKU="})
	if result.Protocol != "TLS" {
		t.Fatalf("base64 result: %+v", result)
	}
	result = engine.Identify(ScanRecord{Port: 80, Banner: "SSH-2.0-OpenSSH_8.9p1" + string(make([]byte, MaxBannerBytes))})
	if result.Protocol != "unknown" {
		t.Fatalf("oversized result: %+v", result)
	}
}

func FuzzFingerprintNeverPanics(f *testing.F) {
	f.Add("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
	engine, err := LoadEngine("../../configs/fingerprints.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, banner string) {
		result := engine.Identify(ScanRecord{Port: 1, Banner: banner})
		if result.Protocol == "" || result.Confidence < 0 || result.Confidence > 1 {
			t.Fatalf("invalid result: %+v", result)
		}
	})
}
