// Package mobile provides mobile testing utilities
package mobile

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ADBController manages Android emulator/device via ADB
type ADBController struct {
	deviceID string
}

// NewADBController creates a new ADB controller
func NewADBController(deviceID string) *ADBController {
	return &ADBController{deviceID: deviceID}
}

// ListDevices lists connected devices
func (a *ADBController) ListDevices(ctx context.Context) ([]string, error) {
	output, err := exec.CommandContext(ctx, "adb", "devices").CombinedOutput()
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(output), "\n")
	devices := []string{}
	for _, line := range lines[1:] { // Skip header
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "device" {
			devices = append(devices, parts[0])
		}
	}
	return devices, nil
}

// SelectDevice selects a device
func (a *ADBController) SelectDevice(deviceID string) {
	a.deviceID = deviceID
}

// adbCmd builds an ADB command with device selector
func (a *ADBController) adbCmd(ctx context.Context, args ...string) *exec.Cmd {
	if a.deviceID != "" {
		args = append([]string{"-s", a.deviceID}, args...)
	}
	return exec.CommandContext(ctx, "adb", args...)
}

// InstallAPK installs an APK
func (a *ADBController) InstallAPK(ctx context.Context, apkPath string) error {
	return a.adbCmd(ctx, "install", "-r", apkPath).Run()
}

// UninstallApp uninstalls an app
func (a *ADBController) UninstallApp(ctx context.Context, packageName string) error {
	return a.adbCmd(ctx, "uninstall", packageName).Run()
}

// LaunchApp launches an app
func (a *ADBController) LaunchApp(ctx context.Context, packageName, activity string) error {
	return a.adbCmd(ctx, "shell", "am", "start", "-n", 
		fmt.Sprintf("%s/%s", packageName, activity)).Run()
}

// StopApp stops an app
func (a *ADBController) StopApp(ctx context.Context, packageName string) error {
	return a.adbCmd(ctx, "shell", "am", "force-stop", packageName).Run()
}

// Screenshot captures a screenshot
func (a *ADBController) Screenshot(ctx context.Context, localPath string) error {
	remotePath := "/sdcard/screenshot.png"
	if err := a.adbCmd(ctx, "shell", "screencap", "-p", remotePath).Run(); err != nil {
		return err
	}
	if err := a.adbCmd(ctx, "pull", remotePath, localPath).Run(); err != nil {
		return err
	}
	return a.adbCmd(ctx, "shell", "rm", remotePath).Run()
}

// RecordScreen records the screen
func (a *ADBController) RecordScreen(ctx context.Context, duration time.Duration, localPath string) error {
	remotePath := "/sdcard/screenrecord.mp4"
	
	// Start recording
	recordCmd := a.adbCmd(ctx, "shell", "screenrecord", "--time-limit", 
		fmt.Sprintf("%d", int(duration.Seconds())), remotePath)
	if err := recordCmd.Start(); err != nil {
		return err
	}
	
	// Wait for duration
	time.Sleep(duration + time.Second)
	
	// Pull file
	if err := a.adbCmd(ctx, "pull", remotePath, localPath).Run(); err != nil {
		return err
	}
	return a.adbCmd(ctx, "shell", "rm", remotePath).Run()
}

// GetLogcat captures logcat output
func (a *ADBController) GetLogcat(ctx context.Context, filter string, lines int) (string, error) {
	args := []string{"shell", "logcat", "-d", fmt.Sprintf("-t %d", lines)}
	if filter != "" {
		args = append(args, "-s", filter)
	}
	output, err := a.adbCmd(ctx, args...).CombinedOutput()
	return string(output), err
}

// PushFile pushes a file to device
func (a *ADBController) PushFile(ctx context.Context, localPath, remotePath string) error {
	return a.adbCmd(ctx, "push", localPath, remotePath).Run()
}

// PullFile pulls a file from device
func (a *ADBController) PullFile(ctx context.Context, remotePath, localPath string) error {
	return a.adbCmd(ctx, "pull", remotePath, localPath).Run()
}

// Shell executes a shell command
func (a *ADBController) Shell(ctx context.Context, command string) (string, error) {
	output, err := a.adbCmd(ctx, "shell", command).CombinedOutput()
	return string(output), err
}

// RunFrida runs a Frida script
func (a *ADBController) RunFrida(ctx context.Context, packageName, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "frida", "-U", "-f", packageName, "-l", script, "--no-pause")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// GetAppData gets app data directory contents
func (a *ADBController) GetAppData(ctx context.Context, packageName string) (string, error) {
	return a.Shell(ctx, fmt.Sprintf("run-as %s ls -la /data/data/%s/", packageName, packageName))
}

// GetInstalledApps lists installed third-party apps
func (a *ADBController) GetInstalledApps(ctx context.Context) ([]string, error) {
	output, err := a.Shell(ctx, "pm list packages -3")
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(output, "\n")
	apps := []string{}
	for _, line := range lines {
		if strings.HasPrefix(line, "package:") {
			apps = append(apps, strings.TrimPrefix(line, "package:"))
		}
	}
	return apps, nil
}

// EnableProxySettings sets proxy for the device
func (a *ADBController) EnableProxySettings(ctx context.Context, host string, port int) error {
	_, err := a.Shell(ctx, fmt.Sprintf("settings put global http_proxy %s:%d", host, port))
	return err
}

// DisableProxySettings removes proxy settings
func (a *ADBController) DisableProxySettings(ctx context.Context) error {
	_, err := a.Shell(ctx, "settings put global http_proxy :0")
	return err
}

// IsRooted checks if device is rooted
func (a *ADBController) IsRooted(ctx context.Context) (bool, error) {
	output, err := a.Shell(ctx, "which su")
	if err != nil {
		return false, nil // Not rooted
	}
	return strings.Contains(output, "/su"), nil
}
