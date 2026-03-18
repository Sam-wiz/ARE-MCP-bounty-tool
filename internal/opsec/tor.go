package opsec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"time"
)

// TorManager manages Tor connections
type TorManager struct {
	socksPort   int
	controlPort int
	running     bool
	cmd         *exec.Cmd
}

// NewTorManager creates a new Tor manager
func NewTorManager(socksPort, controlPort int) *TorManager {
	if socksPort == 0 {
		socksPort = 9050
	}
	if controlPort == 0 {
		controlPort = 9051
	}
	return &TorManager{
		socksPort:   socksPort,
		controlPort: controlPort,
	}
}

// Start starts the Tor service
func (t *TorManager) Start(ctx context.Context) error {
	// Check if Tor is already running
	if t.isRunning() {
		t.running = true
		return nil
	}
	
	// Try to start Tor
	t.cmd = exec.CommandContext(ctx, "tor",
		"--SocksPort", fmt.Sprintf("%d", t.socksPort),
		"--ControlPort", fmt.Sprintf("%d", t.controlPort),
	)
	
	if err := t.cmd.Start(); err != nil {
		// Try using service
		if err := exec.CommandContext(ctx, "sudo", "systemctl", "start", "tor").Run(); err != nil {
			if err := exec.CommandContext(ctx, "brew", "services", "start", "tor").Run(); err != nil {
				return fmt.Errorf("failed to start Tor: %w", err)
			}
		}
	}
	
	// Wait for Tor to be ready
	for i := 0; i < 30; i++ {
		if t.isRunning() {
			t.running = true
			return nil
		}
		time.Sleep(time.Second)
	}
	
	return fmt.Errorf("Tor failed to start within 30 seconds")
}

// Stop stops the Tor service
func (t *TorManager) Stop(ctx context.Context) error {
	if t.cmd != nil && t.cmd.Process != nil {
		return t.cmd.Process.Kill()
	}
	return nil
}

// GetProxyConfig returns proxy config for Tor
func (t *TorManager) GetProxyConfig() ProxyConfig {
	return ProxyConfig{
		Type: "socks5",
		Host: "127.0.0.1",
		Port: t.socksPort,
	}
}

// NewCircuit requests a new Tor circuit
func (t *TorManager) NewCircuit(ctx context.Context) error {
	// Connect to control port and send NEWNYM signal
	// This requires Tor control authentication
	return exec.CommandContext(ctx, "bash", "-c", 
		fmt.Sprintf(`echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc localhost %d`, t.controlPort),
	).Run()
}

// isRunning checks if Tor is running
func (t *TorManager) isRunning() bool {
	// Try to connect to SOCKS port
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("socks5://127.0.0.1:%d", t.socksPort))),
		},
	}
	
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200
}

// GetCurrentIP returns the current exit IP
func (t *TorManager) GetCurrentIP(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("socks5://127.0.0.1:%d", t.socksPort))),
		},
	}
	
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

// VPNManager manages VPN connections
// Supports ProtonVPN CLI (free, with country selection) and OpenVPN
type VPNManager struct {
	provider    string // "protonvpn" or "openvpn"
	configPath  string // OpenVPN config file path
	countryCode string // ISO country code for ProtonVPN (US, NL, JP, etc.)
	connected   bool
}

// NewVPNManager creates a new VPN manager
func NewVPNManager(configPath string) *VPNManager {
	return &VPNManager{
		provider:   "openvpn",
		configPath: configPath,
	}
}

// NewProtonVPNManager creates a VPN manager using ProtonVPN CLI
func NewProtonVPNManager(countryCode string) *VPNManager {
	if countryCode == "" {
		countryCode = "US"
	}
	return &VPNManager{
		provider:    "protonvpn",
		countryCode: countryCode,
	}
}

// Connect connects to VPN based on the provider
func (v *VPNManager) Connect(ctx context.Context) error {
	switch v.provider {
	case "protonvpn":
		return v.connectProtonVPN(ctx)
	case "openvpn":
		return v.connectOpenVPN(ctx)
	default:
		return fmt.Errorf("unsupported VPN provider: %s", v.provider)
	}
}

// connectProtonVPN connects using ProtonVPN CLI with country selection
func (v *VPNManager) connectProtonVPN(ctx context.Context) error {
	// Check if protonvpn-cli is installed
	if _, err := exec.LookPath("protonvpn-cli"); err != nil {
		return fmt.Errorf("protonvpn-cli not installed: run 'pip3 install protonvpn-cli'")
	}

	// Connect to the specified country
	cmd := exec.CommandContext(ctx, "protonvpn-cli", "connect", "--cc", v.countryCode)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ProtonVPN connect failed (country=%s): %s: %w", v.countryCode, string(output), err)
	}

	// Verify connection
	for i := 0; i < 15; i++ {
		if v.isConnected() {
			v.connected = true
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("ProtonVPN connection timeout (country=%s)", v.countryCode)
}

// connectOpenVPN connects using OpenVPN config file
func (v *VPNManager) connectOpenVPN(ctx context.Context) error {
	if v.configPath == "" {
		return fmt.Errorf("no VPN config file specified")
	}

	cmd := exec.CommandContext(ctx, "sudo", "openvpn", "--config", v.configPath, "--daemon")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to connect to VPN: %w", err)
	}

	// Wait for connection
	for i := 0; i < 30; i++ {
		if v.isConnected() {
			v.connected = true
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("VPN connection timeout")
}

// Disconnect disconnects from VPN
func (v *VPNManager) Disconnect(ctx context.Context) error {
	switch v.provider {
	case "protonvpn":
		return exec.CommandContext(ctx, "protonvpn-cli", "disconnect").Run()
	default:
		return exec.CommandContext(ctx, "sudo", "pkill", "openvpn").Run()
	}
}

// SetCountry changes the target country for ProtonVPN
func (v *VPNManager) SetCountry(countryCode string) {
	v.countryCode = countryCode
}

// GetProvider returns the current VPN provider
func (v *VPNManager) GetProvider() string {
	return v.provider
}

// GetCountry returns the current country code
func (v *VPNManager) GetCountry() string {
	return v.countryCode
}

// isConnected checks if VPN is connected
func (v *VPNManager) isConnected() bool {
	// ProtonVPN: parse status output
	if v.provider == "protonvpn" {
		output, err := exec.Command("protonvpn-cli", "status").CombinedOutput()
		if err == nil {
			outStr := string(output)
			for _, line := range []string{"Connected", "connected", "Status: Connected"} {
				if containsAt(outStr, line, 0) {
					return true
				}
			}
		}
		return false
	}

	// OpenVPN: check if tun interface exists
	output, err := exec.Command("ip", "link", "show", "tun0").CombinedOutput()
	if err == nil && len(output) > 0 {
		return true
	}

	// macOS check
	output, err = exec.Command("ifconfig", "utun0").CombinedOutput()
	return err == nil && len(output) > 0
}

// GetCurrentIP returns the current public IP
func (v *VPNManager) GetCurrentIP(ctx context.Context) (string, error) {
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

func mustParseURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}
