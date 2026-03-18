package opsec

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		MACSpoof: MACConfig{
			Enabled:   true,
			Interface: "en0",
		},
		Tor: TorConfig{
			Enabled:   true,
			SocksPort: 9050,
		},
	}

	m := NewManager(cfg)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.config != cfg {
		t.Error("Config not set correctly")
	}
}

func TestNewManager_NilConfig(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager returned nil for nil config")
	}
}

func TestVerificationResult_String(t *testing.T) {
	result := &VerificationResult{
		AllPassed: true,
		Checks: map[string]CheckResult{
			"ip": {Passed: true, Details: "IP is hidden"},
			"dns": {Passed: true, Details: "No DNS leak"},
		},
	}

	s := result.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
}

func TestVerificationResult_String_Failed(t *testing.T) {
	result := &VerificationResult{
		AllPassed: false,
		Checks: map[string]CheckResult{
			"ip":  {Passed: true, Details: "OK"},
			"dns": {Passed: false, Details: "DNS leak detected"},
		},
	}

	s := result.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
}

func TestIsVerified_Default(t *testing.T) {
	m := NewManager(&Config{})
	if m.IsVerified() {
		t.Error("New manager should not be verified")
	}
}
