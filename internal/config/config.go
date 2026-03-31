package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration
type Config struct {
	MongoDB    MongoDBConfig    `yaml:"mongodb"`
	Redis      RedisConfig      `yaml:"redis"`
	Workspace  WorkspaceConfig  `yaml:"workspace"`
	OPSEC      OPSECConfig      `yaml:"opsec"`
	Tools      ToolsConfig      `yaml:"tools"`
	Sandbox    SandboxConfig    `yaml:"sandbox"`
	Validation ValidationConfig `yaml:"validation"`
	Reporting  ReportingConfig  `yaml:"reporting"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// MongoDBConfig for MongoDB connection
type MongoDBConfig struct {
	URI      string `yaml:"uri"`
	Database string `yaml:"database"`
}

// RedisConfig for Redis connection
type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// WorkspaceConfig for workspace management
type WorkspaceConfig struct {
	BaseDir    string `yaml:"base_dir"`
	AutoCreate bool   `yaml:"auto_create"`
}

// OPSECConfig for OPSEC settings
type OPSECConfig struct {
	Enabled    bool            `yaml:"enabled"`
	MACSpoof   MACConfig       `yaml:"mac_spoof"`
	ProxyChain []ProxyConfig   `yaml:"proxy_chain"`
	Tor        TorConfig       `yaml:"tor"`
	VPN        VPNConfig       `yaml:"vpn"`
}

// MACConfig for MAC spoofing
type MACConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
}

// ProxyConfig for proxy settings
type ProxyConfig struct {
	Type     string `yaml:"type"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// TorConfig for Tor settings
type TorConfig struct {
	Enabled     bool `yaml:"enabled"`
	SocksPort   int  `yaml:"socks_port"`
	ControlPort int  `yaml:"control_port"`
}

// VPNConfig for VPN settings
type VPNConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ConfigFile string `yaml:"config_file"`
}

// SandboxConfig for execute_hunting_script sandboxing
type SandboxConfig struct {
	MitmproxyPort   int    `yaml:"mitmproxy_port"`   // default: 8080
	MitmproxyCACert string `yaml:"mitmproxy_ca_cert"` // path to mitmproxy CA cert
	ScriptTimeout   int    `yaml:"script_timeout"`   // default: 600 seconds
}

// ToolsConfig for tool execution
type ToolsConfig struct {
	Timeout       int `yaml:"timeout"`
	MaxConcurrent int `yaml:"max_concurrent"`
	RateLimit     int `yaml:"rate_limit"`
}

// ValidationConfig for validation pipeline
type ValidationConfig struct {
	DefaultLevel        int    `yaml:"default_level"`
	EvidenceDir         string `yaml:"evidence_dir"`
	ScreenshotOnFinding bool   `yaml:"screenshot_on_finding"`
}

// ReportingConfig for report generation
type ReportingConfig struct {
	OutputDir       string   `yaml:"output_dir"`
	Formats         []string `yaml:"formats"`
	IncludePOC      bool     `yaml:"include_poc"`
	IncludeEvidence bool     `yaml:"include_evidence"`
}

// LoggingConfig for logging
type LoggingConfig struct {
	Level     string `yaml:"level"`
	ToFile    bool   `yaml:"to_file"`
	ToMongoDB bool   `yaml:"to_mongodb"`
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	
	// Apply defaults
	cfg.applyDefaults()
	
	return &cfg, nil
}

// LoadOrDefault loads config or returns defaults
func LoadOrDefault(path string) *Config {
	cfg, err := Load(path)
	if err != nil {
		cfg = &Config{}
		cfg.applyDefaults()
	}
	return cfg
}

// applyDefaults sets default values
func (c *Config) applyDefaults() {
	if c.MongoDB.URI == "" {
		c.MongoDB.URI = "mongodb://localhost:27017"
	}
	if c.MongoDB.Database == "" {
		c.MongoDB.Database = "hack_ai_v2"
	}
	if c.Redis.Addr == "" {
		c.Redis.Addr = "localhost:6379"
	}
	if c.Tools.Timeout == 0 {
		c.Tools.Timeout = 3600
	}
	if c.Tools.MaxConcurrent == 0 {
		c.Tools.MaxConcurrent = 5
	}
	if c.Tools.RateLimit == 0 {
		c.Tools.RateLimit = 10
	}
	if c.Validation.DefaultLevel == 0 {
		c.Validation.DefaultLevel = 3
	}
	if c.Sandbox.MitmproxyPort == 0 {
		c.Sandbox.MitmproxyPort = 8080
	}
	if c.Sandbox.ScriptTimeout == 0 {
		c.Sandbox.ScriptTimeout = 600
	}
	if c.Sandbox.MitmproxyCACert == "" {
		home, _ := os.UserHomeDir()
		defaultCA := home + "/.mitmproxy/mitmproxy-ca-cert.pem"
		if _, err := os.Stat(defaultCA); err == nil {
			c.Sandbox.MitmproxyCACert = defaultCA
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if len(c.Reporting.Formats) == 0 {
		c.Reporting.Formats = []string{"json", "markdown"}
	}
}

// Save saves configuration to file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
