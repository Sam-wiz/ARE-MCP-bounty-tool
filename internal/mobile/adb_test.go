package mobile

import (
	"context"
	"testing"
)

func TestNewADBController(t *testing.T) {
	ctrl := NewADBController("emulator-5554")
	if ctrl == nil {
		t.Fatal("NewADBController returned nil")
	}
	if ctrl.deviceID != "emulator-5554" {
		t.Errorf("Expected device ID 'emulator-5554', got %s", ctrl.deviceID)
	}
}

func TestNewADBController_Empty(t *testing.T) {
	ctrl := NewADBController("")
	if ctrl == nil {
		t.Fatal("NewADBController returned nil")
	}
	if ctrl.deviceID != "" {
		t.Errorf("Expected empty device ID, got %s", ctrl.deviceID)
	}
}

func TestSelectDevice(t *testing.T) {
	ctrl := NewADBController("")
	ctrl.SelectDevice("device-123")
	if ctrl.deviceID != "device-123" {
		t.Errorf("Expected 'device-123', got %s", ctrl.deviceID)
	}
}

func TestAdbCmd_WithDevice(t *testing.T) {
	ctrl := NewADBController("emulator-5554")
	ctx := context.Background()
	cmd := ctrl.adbCmd(ctx, "shell", "ls")

	args := cmd.Args
	// Should be: adb -s emulator-5554 shell ls
	if len(args) < 5 {
		t.Fatalf("Expected at least 5 args, got %d: %v", len(args), args)
	}
	if args[1] != "-s" || args[2] != "emulator-5554" {
		t.Errorf("Expected -s emulator-5554, got %v", args[1:3])
	}
}

func TestAdbCmd_WithoutDevice(t *testing.T) {
	ctrl := NewADBController("")
	ctx := context.Background()
	cmd := ctrl.adbCmd(ctx, "devices")

	args := cmd.Args
	// Should be: adb devices
	if len(args) != 2 {
		t.Fatalf("Expected 2 args, got %d: %v", len(args), args)
	}
}
