package scopepolicy

import (
	"os"
	"testing"
)

func TestAllowTargetDomainAndIP(t *testing.T) {
	policy := &Policy{
		SchemaVersion: 1,
		RootDomain:    "example.test",
		ScopeDomains:  []string{"example.test", "*.example.test"},
		ScopeIps:      []string{"192.0.2.0/24"},
		Exclusions:    []string{"blocked.example.test"},
		PolicyHash:    "abc",
	}
	if err := AllowTarget(policy, "https://example.test/"); err != nil {
		t.Fatalf("expected allow apex: %v", err)
	}
	if err := AllowTarget(policy, "https://api.example.test/"); err != nil {
		t.Fatalf("expected allow subdomain: %v", err)
	}
	if err := AllowTarget(policy, "https://blocked.example.test/"); err == nil {
		t.Fatal("expected exclusion")
	}
	if err := AllowTarget(policy, "https://192.0.2.10/"); err != nil {
		t.Fatalf("expected allow IP: %v", err)
	}
	if err := AllowTarget(policy, "https://198.51.100.10/"); err == nil {
		t.Fatal("expected IP deny")
	}
}

func TestLoadFromEnvOptional(t *testing.T) {
	os.Unsetenv("GHOSTRECON_SCOPE_POLICY_FILE")
	os.Unsetenv("GHOSTRECON_SCOPE_POLICY_JSON")
	os.Unsetenv("GHOSTRECON_SCOPE_POLICY_HASH")
	policy, err := LoadFromEnv()
	if err != nil || policy != nil {
		t.Fatalf("expected nil policy, got %#v err=%v", policy, err)
	}
}

func TestLoadFromEnvHash(t *testing.T) {
	os.Setenv("GHOSTRECON_SCOPE_POLICY_JSON", `{"schemaVersion":1,"rootDomain":"example.test","engagementId":"E1","scopeDomains":["example.test"],"scopeIps":[],"exclusions":[],"policyHash":"deadbeef"}`)
	os.Setenv("GHOSTRECON_SCOPE_POLICY_HASH", "deadbeef")
	t.Cleanup(func() {
		os.Unsetenv("GHOSTRECON_SCOPE_POLICY_JSON")
		os.Unsetenv("GHOSTRECON_SCOPE_POLICY_HASH")
	})
	policy, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if policy.RootDomain != "example.test" {
		t.Fatalf("unexpected %#v", policy)
	}
}
