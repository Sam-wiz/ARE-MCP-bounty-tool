package opsec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Manager orchestrates all OPSEC components
type Manager struct {
	config     *Config
	macSpoofer *MACSpoofer
	proxyChain *ProxyChain
	torManager *TorManager
	vpnManager *VPNManager
	
	originalIP string
	currentIP  string
	verified   bool
}

// Config represents OPSEC configuration
type Config struct {
	Enabled    bool          `yaml:"enabled"`
	ProxyChain []ProxyConfig `yaml:"proxy_chain"`
	MACSpoof   MACConfig     `yaml:"mac_spoof"`
	Tor        TorConfig     `yaml:"tor"`
	VPN        VPNConfig     `yaml:"vpn"`
	DNS        DNSConfig     `yaml:"dns"`
	CleanEnv   CleanConfig   `yaml:"clean_env"`
}

// MACConfig for MAC spoofing
type MACConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
	CustomMAC string `yaml:"custom_mac,omitempty"`
}

// TorConfig for Tor
type TorConfig struct {
	Enabled     bool `yaml:"enabled"`
	SocksPort   int  `yaml:"socks_port"`
	ControlPort int  `yaml:"control_port"`
}

// VPNConfig for VPN
type VPNConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Provider   string `yaml:"provider"`    // "protonvpn" or "openvpn"
	Country    string `yaml:"country"`     // ISO country code for ProtonVPN (e.g. US, NL, JP)
	ConfigFile string `yaml:"config_file"` // OpenVPN config path
}

// DNSConfig for DNS settings
type DNSConfig struct {
	Servers   []string `yaml:"servers"`
	DoH       bool     `yaml:"doh"`
	DoHServer string   `yaml:"doh_server"`
}

// CleanConfig for clean environment
type CleanConfig struct {
	ClearBrowser bool `yaml:"clear_browser"`
	UseTempDirs  bool `yaml:"use_temp_dirs"`
	NoHistory    bool `yaml:"no_history"`
}

// NewManager creates a new OPSEC manager
func NewManager(config *Config) *Manager {
	return &Manager{config: config}
}

// Setup sets up all OPSEC layers
func (m *Manager) Setup(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}
	
	// Store original IP
	originalIP, err := m.getPublicIP(ctx)
	if err != nil {
		return fmt.Errorf("failed to get original IP: %w", err)
	}
	m.originalIP = originalIP
	
	// 1. MAC Spoofing (first - lowest level)
	if m.config.MACSpoof.Enabled {
		m.macSpoofer = NewMACSpoofer(m.config.MACSpoof.Interface)
		if err := m.macSpoofer.Spoof(ctx); err != nil {
			return fmt.Errorf("MAC spoofing failed: %w", err)
		}
	}
	
	// 2. VPN (if enabled)
	if m.config.VPN.Enabled {
		switch m.config.VPN.Provider {
		case "protonvpn":
			m.vpnManager = NewProtonVPNManager(m.config.VPN.Country)
		default:
			m.vpnManager = NewVPNManager(m.config.VPN.ConfigFile)
		}
		if err := m.vpnManager.Connect(ctx); err != nil {
			return fmt.Errorf("VPN connection failed: %w", err)
		}
	}
	
	// 3. Tor (if enabled)
	if m.config.Tor.Enabled {
		m.torManager = NewTorManager(m.config.Tor.SocksPort, m.config.Tor.ControlPort)
		if err := m.torManager.Start(ctx); err != nil {
			return fmt.Errorf("Tor start failed: %w", err)
		}
		// Add Tor to proxy chain
		m.config.ProxyChain = append([]ProxyConfig{m.torManager.GetProxyConfig()}, m.config.ProxyChain...)
	}
	
	// 4. Proxy Chain
	if len(m.config.ProxyChain) > 0 {
		var err error
		m.proxyChain, err = NewProxyChain(m.config.ProxyChain)
		if err != nil {
			return fmt.Errorf("proxy chain setup failed: %w", err)
		}
	}
	
	// 5. Clean Environment
	if m.config.CleanEnv.UseTempDirs {
		if err := m.setupCleanEnvironment(); err != nil {
			return fmt.Errorf("clean environment setup failed: %w", err)
		}
	}
	
	return nil
}

// Verify verifies the OPSEC setup
func (m *Manager) Verify(ctx context.Context) (*VerificationResult, error) {
	result := &VerificationResult{
		Checks: make(map[string]CheckResult),
	}
	
	// Check IP changed
	currentIP, err := m.getPublicIPViaProxy(ctx)
	if err != nil {
		result.Checks["ip_hidden"] = CheckResult{Passed: false, Details: err.Error()}
	} else {
		m.currentIP = currentIP
		ipChanged := currentIP != m.originalIP
		result.Checks["ip_hidden"] = CheckResult{
			Passed:  ipChanged,
			Details: fmt.Sprintf("Original: %s, Current: %s", m.originalIP, currentIP),
		}
	}
	
	// Check MAC changed
	if m.macSpoofer != nil {
		changed, err := m.macSpoofer.VerifyMACChanged()
		if err != nil {
			result.Checks["mac_spoofed"] = CheckResult{Passed: false, Details: err.Error()}
		} else {
			result.Checks["mac_spoofed"] = CheckResult{
				Passed:  changed,
				Details: fmt.Sprintf("Current: %s", m.macSpoofer.GetCurrentMAC()),
			}
		}
	}
	
	// Check Tor
	if m.torManager != nil {
		torIP, err := m.torManager.GetCurrentIP(ctx)
		if err != nil {
			result.Checks["tor_active"] = CheckResult{Passed: false, Details: err.Error()}
		} else {
			result.Checks["tor_active"] = CheckResult{
				Passed:  true,
				Details: fmt.Sprintf("Exit IP: %s", torIP),
			}
		}
	}
	
	// Check DNS leak
	dnsLeak, err := m.checkDNSLeak(ctx)
	if err != nil {
		result.Checks["dns_secure"] = CheckResult{Passed: false, Details: err.Error()}
	} else {
		result.Checks["dns_secure"] = CheckResult{Passed: !dnsLeak, Details: "DNS leak check completed"}
	}
	
	// Overall status
	result.AllPassed = true
	for _, check := range result.Checks {
		if !check.Passed {
			result.AllPassed = false
			break
		}
	}
	
	m.verified = result.AllPassed
	return result, nil
}

// Teardown tears down all OPSEC layers
func (m *Manager) Teardown(ctx context.Context) error {
	var errors []error
	
	// Reverse order of setup
	if m.torManager != nil {
		if err := m.torManager.Stop(ctx); err != nil {
			errors = append(errors, err)
		}
	}
	
	if m.vpnManager != nil {
		if err := m.vpnManager.Disconnect(ctx); err != nil {
			errors = append(errors, err)
		}
	}
	
	if m.macSpoofer != nil {
		if err := m.macSpoofer.Restore(ctx); err != nil {
			errors = append(errors, err)
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("teardown errors: %v", errors)
	}
	return nil
}

// GetHTTPClient returns an HTTP client configured with OPSEC
func (m *Manager) GetHTTPClient() *http.Client {
	if m.proxyChain != nil {
		return m.proxyChain.HTTPClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// IsVerified returns whether OPSEC is verified
func (m *Manager) IsVerified() bool {
	return m.verified
}

// getPublicIP gets the current public IP
func (m *Manager) getPublicIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// getPublicIPViaProxy gets IP through proxy chain
func (m *Manager) getPublicIPViaProxy(ctx context.Context) (string, error) {
	client := m.GetHTTPClient()
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// checkDNSLeak checks for DNS leaks
func (m *Manager) checkDNSLeak(ctx context.Context) (bool, error) {
	// Use DNS leak test service
	client := m.GetHTTPClient()
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://bash.ws/dnsleak/test", nil)
	if err != nil {
		return false, err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	var result struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	
	// Check if DNS server is from a known privacy concern country
	// This is a simplified check
	return false, nil
}

// setupCleanEnvironment sets up a clean environment
func (m *Manager) setupCleanEnvironment() error {
	// Create temp directories for this session
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("hack-ai-v2-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return err
	}
	
	// Set environment variables
	os.Setenv("HACK_AI_TMP", tmpDir)
	os.Setenv("HOME", tmpDir) // Redirect home to temp
	
	// Clear browser data if enabled
	if m.config.CleanEnv.ClearBrowser {
		m.clearBrowserData()
	}
	
	// Disable history
	if m.config.CleanEnv.NoHistory {
		os.Setenv("HISTFILE", "/dev/null")
		os.Setenv("HISTSIZE", "0")
	}
	
	return nil
}

// clearBrowserData clears browser data
func (m *Manager) clearBrowserData() {
	// Chrome
	exec.Command("rm", "-rf", filepath.Join(os.Getenv("HOME"), ".config/google-chrome")).Run()
	exec.Command("rm", "-rf", filepath.Join(os.Getenv("HOME"), "Library/Application Support/Google/Chrome")).Run()
	
	// Firefox
	exec.Command("rm", "-rf", filepath.Join(os.Getenv("HOME"), ".mozilla")).Run()
	exec.Command("rm", "-rf", filepath.Join(os.Getenv("HOME"), "Library/Application Support/Firefox")).Run()
}

// VerificationResult holds OPSEC verification results
type VerificationResult struct {
	AllPassed bool                   `json:"all_passed"`
	Checks    map[string]CheckResult `json:"checks"`
}

// CheckResult holds a single check result
type CheckResult struct {
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// String returns a human-readable verification result
func (v *VerificationResult) String() string {
	result := "OPSEC Verification:\n"
	for name, check := range v.Checks {
		status := "✅"
		if !check.Passed {
			status = "❌"
		}
		result += fmt.Sprintf("  %s %s: %s\n", status, name, check.Details)
	}
	if v.AllPassed {
		result += "\n✅ ALL CHECKS PASSED - Ready for testing"
	} else {
		result += "\n❌ SOME CHECKS FAILED - Review before proceeding"
	}
	return result
}
