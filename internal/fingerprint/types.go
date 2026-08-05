package fingerprint

type ScanRecord struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Banner       string `json:"banner"`
	BannerBase64 string `json:"banner_base64,omitempty"`
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
