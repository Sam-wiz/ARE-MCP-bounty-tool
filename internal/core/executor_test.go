package core

import (
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// TestBuildCommand_SubfinderArgs tests that subfinder plugin args are correctly substituted
func TestBuildCommand_SubfinderArgs(t *testing.T) {
	plugin := &types.PluginDefinition{
		Name: "subfinder",
		Execute: types.ExecuteConfig{
			Command: "subfinder -d {domain} -silent {extra_args}",
			Input: map[string]types.InputParam{
				"domain": {Type: "string", Required: true},
				"extra_args": {Type: "string", Required: false, Default: ""},
			},
		},
	}

	cmd, err := buildCommand(plugin, map[string]interface{}{
		"domain": "example.com",
	})
	if err != nil {
		t.Fatalf("buildCommand failed: %v", err)
	}

	// Should contain the shell-escaped domain
	if cmd != "subfinder -d 'example.com' -silent" {
		t.Errorf("unexpected command: %s", cmd)
	}
}

// TestBuildCommand_NucleiArgs tests nuclei plugin with targets_file and severity
func TestBuildCommand_NucleiArgs(t *testing.T) {
	plugin := &types.PluginDefinition{
		Name: "nuclei",
		Execute: types.ExecuteConfig{
			Command: "nuclei -l {targets_file} -severity {severity} -j -silent {extra_args}",
			Input: map[string]types.InputParam{
				"targets_file": {Type: "file", Required: true},
				"severity":     {Type: "string", Required: false, Default: "critical,high,medium"},
				"extra_args":   {Type: "string", Required: false, Default: ""},
			},
		},
	}

	cmd, err := buildCommand(plugin, map[string]interface{}{
		"targets_file": "/tmp/targets.txt",
		"severity":     "critical,high",
	})
	if err != nil {
		t.Fatalf("buildCommand failed: %v", err)
	}

	expected := "nuclei -l '/tmp/targets.txt' -severity 'critical,high' -j -silent"
	if cmd != expected {
		t.Errorf("expected: %s\ngot:      %s", expected, cmd)
	}
}

// TestBuildCommand_MissingRequired tests that missing required args return error
func TestBuildCommand_MissingRequired(t *testing.T) {
	plugin := &types.PluginDefinition{
		Name: "subfinder",
		Execute: types.ExecuteConfig{
			Command: "subfinder -d {domain} -silent",
			Input: map[string]types.InputParam{
				"domain": {Type: "string", Required: true},
			},
		},
	}

	_, err := buildCommand(plugin, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
}

// TestBuildCommand_DefaultValues tests that defaults are applied for optional params
func TestBuildCommand_DefaultValues(t *testing.T) {
	plugin := &types.PluginDefinition{
		Name: "httpx",
		Execute: types.ExecuteConfig{
			Command: "httpx -l {input_file} -json -silent {extra_args}",
			Input: map[string]types.InputParam{
				"input_file": {Type: "file", Required: true},
				"extra_args": {Type: "string", Required: false, Default: "-tech-detect -status-code -title"},
			},
		},
	}

	cmd, err := buildCommand(plugin, map[string]interface{}{
		"input_file": "/tmp/hosts.txt",
	})
	if err != nil {
		t.Fatalf("buildCommand failed: %v", err)
	}

	expected := "httpx -l '/tmp/hosts.txt' -json -silent -tech-detect -status-code -title"
	if cmd != expected {
		t.Errorf("expected: %s\ngot:      %s", expected, cmd)
	}
}

// TestBuildCommand_WrongArgName tests that wrong arg names cause placeholder to remain empty
func TestBuildCommand_WrongArgName(t *testing.T) {
	plugin := &types.PluginDefinition{
		Name: "httpx",
		Execute: types.ExecuteConfig{
			Command: "httpx -l {input_file} -json -silent",
			Input: map[string]types.InputParam{
				"input_file": {Type: "file", Required: true},
			},
		},
	}

	// This was the OLD bug: passing "target" instead of "input_file"
	_, err := buildCommand(plugin, map[string]interface{}{
		"target": "example.com", // WRONG key — should be "input_file"
	})
	// Should fail because input_file is required and "target" doesn't match
	if err == nil {
		t.Fatal("expected error when passing wrong arg name for required param")
	}
}

// TestShellEscape tests shell escaping
func TestShellEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "'example.com'"},
		{"it's a test", "'it'\\''s a test'"},
		{"hello world", "'hello world'"},
		{"", "''"},
	}

	for _, tt := range tests {
		result := ShellEscape(tt.input)
		if result != tt.expected {
			t.Errorf("ShellEscape(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
