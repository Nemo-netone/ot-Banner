package fingerprint

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

const MaxBannerBytes = 64 * 1024

type Rule struct {
	ID           string  `json:"id"`
	Priority     int     `json:"priority"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	Pattern      string  `json:"pattern"`
	VersionGroup string  `json:"version_group"`
	OSGroup      string  `json:"os_group"`
	Confidence   float64 `json:"confidence"`
	PortHint     []int   `json:"port_hint"`
	compiled     *regexp.Regexp
}

type OSHintRule struct {
	Name            string  `json:"name"`
	Pattern         string  `json:"pattern"`
	ConfidenceBonus float64 `json:"confidence_bonus"`
	compiled        *regexp.Regexp
}

type ruleFile struct {
	Version int          `json:"version"`
	Rules   []Rule       `json:"rules"`
	OSHints []OSHintRule `json:"os_hints"`
}

type Engine struct {
	rules   []Rule
	osHints []OSHintRule
}

func LoadEngine(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var file ruleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d", file.Version)
	}
	seen := make(map[string]struct{}, len(file.Rules))
	for i := range file.Rules {
		rule := &file.Rules[i]
		if rule.ID == "" || rule.Protocol == "" || rule.Pattern == "" {
			return nil, fmt.Errorf("rule %q has missing required fields", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return nil, fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.Confidence < 0 || rule.Confidence > 1 {
			return nil, fmt.Errorf("rule %q confidence must be between 0 and 1", rule.ID)
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if rule.VersionGroup != "" && compiled.SubexpIndex(rule.VersionGroup) < 0 {
			return nil, fmt.Errorf("rule %q version group %q does not exist", rule.ID, rule.VersionGroup)
		}
		if rule.OSGroup != "" && compiled.SubexpIndex(rule.OSGroup) < 0 {
			return nil, fmt.Errorf("rule %q os group %q does not exist", rule.ID, rule.OSGroup)
		}
		rule.compiled = compiled
	}
	for i := range file.OSHints {
		hint := &file.OSHints[i]
		compiled, err := regexp.Compile(hint.Pattern)
		if err != nil {
			return nil, fmt.Errorf("os hint %q: %w", hint.Name, err)
		}
		hint.compiled = compiled
	}
	sort.SliceStable(file.Rules, func(i, j int) bool {
		if file.Rules[i].Priority != file.Rules[j].Priority {
			return file.Rules[i].Priority > file.Rules[j].Priority
		}
		return file.Rules[i].ID < file.Rules[j].ID
	})
	return &Engine{rules: file.Rules, osHints: file.OSHints}, nil
}

func (e *Engine) Ready() bool { return e != nil && len(e.rules) > 0 }

func (e *Engine) Identify(record ScanRecord) FingerprintResult {
	result := FingerprintResult{IP: record.IP, Port: record.Port, Protocol: "unknown"}
	if e == nil {
		return result
	}
	raw, err := bannerBytes(record)
	if err != nil || len(raw) == 0 || len(raw) > MaxBannerBytes {
		return result
	}
	view := normalize(raw)
	var best *candidate
	for i := range e.rules {
		rule := &e.rules[i]
		match := rule.compiled.FindStringSubmatchIndex(view.matchText)
		if match == nil {
			continue
		}
		version := capture(view.matchText, match, rule.compiled, rule.VersionGroup)
		osHint := capture(view.matchText, match, rule.compiled, rule.OSGroup)
		candidate := candidate{rule: rule, version: version, osHint: osHint, score: rule.Confidence}
		if best == nil || candidate.betterThan(best) {
			best = &candidate
		}
	}
	if best == nil {
		return result
	}
	result.Protocol, result.Product = best.rule.Protocol, best.rule.Product
	result.Version, result.OSHint = best.version, best.osHint
	result.Confidence = clamp(best.score)
	for _, hint := range e.osHints {
		if result.OSHint == "" && hint.compiled.MatchString(view.printable) {
			result.OSHint = hint.Name
		}
	}
	return result
}

type candidate struct {
	rule            *Rule
	version, osHint string
	score           float64
}

func (c *candidate) betterThan(other *candidate) bool {
	if c.rule.Priority != other.rule.Priority {
		return c.rule.Priority > other.rule.Priority
	}
	if c.score != other.score {
		return c.score > other.score
	}
	return c.rule.ID < other.rule.ID
}

type normalizedBanner struct{ printable, matchText string }

func normalize(raw []byte) normalizedBanner {
	printable := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b <= 0x7e) {
			printable = append(printable, b)
		}
	}
	return normalizedBanner{printable: string(printable), matchText: string(raw)}
}

func bannerBytes(record ScanRecord) ([]byte, error) {
	if record.BannerBase64 != "" {
		return base64.StdEncoding.DecodeString(record.BannerBase64)
	}
	value := record.Banner
	if decoded, err := decodeHexEscapes(value); err == nil {
		value = string(decoded)
	}
	return []byte(value), nil
}

func decodeHexEscapes(value string) ([]byte, error) {
	var out bytes.Buffer
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) && value[i+1] == 'x' {
			decoded := make([]byte, 1)
			if _, err := hex.Decode(decoded, []byte(value[i+2:i+4])); err != nil {
				return nil, err
			}
			out.WriteByte(decoded[0])
			i += 3
		} else {
			out.WriteByte(value[i])
		}
	}
	return out.Bytes(), nil
}

func capture(text string, indexes []int, re *regexp.Regexp, name string) string {
	if name == "" {
		return ""
	}
	i := re.SubexpIndex(name)
	if i < 0 || indexes[2*i] < 0 {
		return ""
	}
	return text[indexes[2*i]:indexes[2*i+1]]
}
func clamp(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
