// Package scopepolicy loads and enforces a sealed GHOSTRECON scope policy
// delivered via environment variables for CLI v1.
package scopepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Policy is the public sealed payload (no authorizationBinding).
type Policy struct {
	SchemaVersion int      `json:"schemaVersion"`
	RootDomain    string   `json:"rootDomain"`
	EngagementID  string   `json:"engagementId"`
	ScopeDomains  []string `json:"scopeDomains"`
	ScopeIps      []string `json:"scopeIps"`
	Exclusions    []string `json:"exclusions"`
	PolicyHash    string   `json:"policyHash"`
}

// LoadFromEnv reads GHOSTRECON_SCOPE_POLICY_FILE or GHOSTRECON_SCOPE_POLICY_JSON.
// When neither is set, returns (nil, nil) — enforcement is optional for bare CLI use.
func LoadFromEnv() (*Policy, error) {
	filePath := strings.TrimSpace(os.Getenv("GHOSTRECON_SCOPE_POLICY_FILE"))
	rawJSON := strings.TrimSpace(os.Getenv("GHOSTRECON_SCOPE_POLICY_JSON"))
	expectedHash := strings.TrimSpace(strings.ToLower(os.Getenv("GHOSTRECON_SCOPE_POLICY_HASH")))

	var raw []byte
	switch {
	case filePath != "":
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading scope policy file: %w", err)
		}
		raw = content
	case rawJSON != "":
		raw = []byte(rawJSON)
	default:
		return nil, nil
	}

	var policy Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, fmt.Errorf("parsing scope policy: %w", err)
	}
	if policy.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported scope policy schemaVersion %d", policy.SchemaVersion)
	}
	if expectedHash != "" {
		got := strings.ToLower(strings.TrimSpace(policy.PolicyHash))
		if got == "" {
			sum := sha256.Sum256(raw)
			got = hex.EncodeToString(sum[:])
		}
		// policyHash is computed by GHOSTRECON over the sealed object (may include
		// fields omitted from the public JSON). Compare the declared hash only.
		if got != expectedHash {
			return nil, fmt.Errorf("scope policy hash mismatch")
		}
	}
	return &policy, nil
}

// AllowTarget reports whether targetURL host is inside the sealed allowlist.
func AllowTarget(policy *Policy, targetURL string) error {
	if policy == nil {
		return nil
	}
	host := strings.TrimSpace(strings.ToLower(hostFromURL(targetURL)))
	if host == "" {
		return fmt.Errorf("scope policy: empty target host")
	}
	if matchesAnyExclusion(host, policy.Exclusions) {
		return fmt.Errorf("scope policy: host %q is excluded", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if len(policy.ScopeIps) == 0 {
			return fmt.Errorf("scope policy: IP %q not in allowlist", host)
		}
		for _, rule := range policy.ScopeIps {
			if ipMatchesRule(ip, rule) {
				return nil
			}
		}
		return fmt.Errorf("scope policy: IP %q not in allowlist", host)
	}
	if len(policy.ScopeDomains) == 0 {
		return fmt.Errorf("scope policy: host %q not in domain allowlist", host)
	}
	for _, rule := range policy.ScopeDomains {
		if hostnameMatchesRule(host, rule) {
			return nil
		}
	}
	return fmt.Errorf("scope policy: host %q not in domain allowlist", host)
}

func hostFromURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		// Minimal parse without importing net/url for path edge cases.
		rest := value
		if idx := strings.Index(rest, "://"); idx >= 0 {
			rest = rest[idx+3:]
		}
		if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
			rest = rest[:idx]
		}
		if idx := strings.Index(rest, "@"); idx >= 0 {
			rest = rest[idx+1:]
		}
		if host, _, err := net.SplitHostPort(rest); err == nil {
			return host
		}
		return strings.Trim(rest, "[]")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}

func matchesAnyExclusion(host string, rules []string) bool {
	for _, rule := range rules {
		normalized := strings.TrimSpace(strings.ToLower(rule))
		if normalized == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if ipMatchesRule(ip, normalized) {
				return true
			}
			continue
		}
		if hostnameMatchesRule(host, normalized) {
			return true
		}
	}
	return false
}

func hostnameMatchesRule(host, rule string) bool {
	rule = strings.TrimSpace(strings.ToLower(rule))
	host = strings.TrimSuffix(host, ".")
	rule = strings.TrimSuffix(rule, ".")
	if rule == "" || host == "" {
		return false
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:] // ".example.test"
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(rule, "*.")
	}
	return host == rule
}

func ipMatchesRule(ip net.IP, rule string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" || ip == nil {
		return false
	}
	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}
	parsed := net.ParseIP(rule)
	if parsed == nil {
		return false
	}
	return parsed.Equal(ip)
}
