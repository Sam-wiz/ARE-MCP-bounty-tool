// Package opsec provides operational security utilities
package opsec

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// MACSpoofer handles MAC address spoofing
type MACSpoofer struct {
	originalMAC  string
	currentMAC   string
	iface        string
}

// NewMACSpoofer creates a new MAC spoofer
func NewMACSpoofer(iface string) *MACSpoofer {
	if iface == "" {
		iface = detectDefaultInterface()
	}
	return &MACSpoofer{iface: iface}
}

// Spoof changes the MAC address
func (m *MACSpoofer) Spoof(ctx context.Context) error {
	// Store original MAC
	original, err := m.getCurrentMAC()
	if err != nil {
		return fmt.Errorf("failed to get current MAC: %w", err)
	}
	m.originalMAC = original

	// Generate random MAC
	newMAC := generateRandomMAC()
	
	// Apply new MAC based on OS
	if err := m.setMAC(ctx, newMAC); err != nil {
		return fmt.Errorf("failed to set MAC: %w", err)
	}
	
	m.currentMAC = newMAC
	return nil
}

// Restore restores the original MAC address
func (m *MACSpoofer) Restore(ctx context.Context) error {
	if m.originalMAC == "" {
		return nil
	}
	return m.setMAC(ctx, m.originalMAC)
}

// GetCurrentMAC returns the current MAC address
func (m *MACSpoofer) GetCurrentMAC() string {
	mac, _ := m.getCurrentMAC()
	return mac
}

// GetOriginalMAC returns the original MAC address
func (m *MACSpoofer) GetOriginalMAC() string {
	return m.originalMAC
}

// getCurrentMAC gets the current MAC address of the interface
func (m *MACSpoofer) getCurrentMAC() (string, error) {
	iface, err := net.InterfaceByName(m.iface)
	if err != nil {
		return "", err
	}
	return iface.HardwareAddr.String(), nil
}

// setMAC sets the MAC address based on OS
func (m *MACSpoofer) setMAC(ctx context.Context, mac string) error {
	switch runtime.GOOS {
	case "darwin":
		return m.setMACDarwin(ctx, mac)
	case "linux":
		return m.setMACLinux(ctx, mac)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// setMACDarwin sets MAC on macOS
func (m *MACSpoofer) setMACDarwin(ctx context.Context, mac string) error {
	// Disconnect from WiFi first
	exec.CommandContext(ctx, "networksetup", "-setairportpower", m.iface, "off").Run()
	
	// Set MAC
	cmd := exec.CommandContext(ctx, "sudo", "ifconfig", m.iface, "ether", mac)
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Reconnect
	exec.CommandContext(ctx, "networksetup", "-setairportpower", m.iface, "on").Run()
	return nil
}

// setMACLinux sets MAC on Linux
func (m *MACSpoofer) setMACLinux(ctx context.Context, mac string) error {
	// Bring interface down
	if err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", m.iface, "down").Run(); err != nil {
		return err
	}
	
	// Set MAC
	if err := exec.CommandContext(ctx, "sudo", "ip", "link", "set", m.iface, "address", mac).Run(); err != nil {
		return err
	}
	
	// Bring interface up
	return exec.CommandContext(ctx, "sudo", "ip", "link", "set", m.iface, "up").Run()
}

// generateRandomMAC generates a random MAC address
func generateRandomMAC() string {
	// Common vendor prefixes (to look legitimate)
	vendors := []string{
		"00:50:56", // VMware
		"00:0C:29", // VMware
		"00:1A:11", // Google
		"00:25:00", // Apple
		"F8:1E:DF", // Apple
	}
	
	// Pick random vendor
	vendor := vendors[randomInt(len(vendors))]
	
	// Generate random suffix
	suffix := fmt.Sprintf("%02X:%02X:%02X", randomByte(), randomByte(), randomByte())
	
	return vendor + ":" + suffix
}

// detectDefaultInterface detects the default network interface
func detectDefaultInterface() string {
	switch runtime.GOOS {
	case "darwin":
		// Try common macOS interfaces
		for _, iface := range []string{"en0", "en1"} {
			if _, err := net.InterfaceByName(iface); err == nil {
				return iface
			}
		}
	case "linux":
		// Try common Linux interfaces
		for _, iface := range []string{"eth0", "wlan0", "enp0s3"} {
			if _, err := net.InterfaceByName(iface); err == nil {
				return iface
			}
		}
	}
	return "eth0"
}

// VerifyMACChanged checks if MAC was successfully changed
func (m *MACSpoofer) VerifyMACChanged() (bool, error) {
	current, err := m.getCurrentMAC()
	if err != nil {
		return false, err
	}
	return strings.ToUpper(current) != strings.ToUpper(m.originalMAC), nil
}

// helper functions
func randomInt(max int) int {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return int(b[0]) % max
}

func randomByte() byte {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return b[0]
}
