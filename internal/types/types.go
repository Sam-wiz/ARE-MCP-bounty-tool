package types

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ============================================================================
// TOOL DEFINITIONS
// ============================================================================

// ToolDefinition represents a tool available via MCP
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock represents a content block in MCP responses
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ============================================================================
// PLUGIN SYSTEM
// ============================================================================

// PluginDefinition represents a tool plugin loaded from YAML
type PluginDefinition struct {
	Name         string            `yaml:"name"`
	Category     string            `yaml:"category"`
	Version      string            `yaml:"version"`
	Description  string            `yaml:"description"`
	Install      InstallConfig     `yaml:"install"`
	Execute      ExecuteConfig     `yaml:"execute"`
	Parse        ParseConfig       `yaml:"parse"`
	Capabilities []string          `yaml:"capabilities"`
	Resources    ResourceConfig    `yaml:"resources"`
}

// InstallConfig defines how to install a tool
type InstallConfig struct {
	Method  string `yaml:"method"` // go, pip, apt, brew, binary
	Command string `yaml:"command"`
	Verify  string `yaml:"verify"`
}

// ExecuteConfig defines how to execute a tool
type ExecuteConfig struct {
	Command string                 `yaml:"command"`
	Input   map[string]InputParam  `yaml:"input"`
	Output  OutputConfig           `yaml:"output"`
	Timeout int                    `yaml:"timeout"` // seconds
}

// InputParam defines an input parameter for a tool
type InputParam struct {
	Type        string `yaml:"type"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// OutputConfig defines how to parse tool output
type OutputConfig struct {
	Format string `yaml:"format"` // lines, json, xml
	Type   string `yaml:"type"`   // subdomains, urls, findings, etc.
}

// ParseConfig defines how to parse tool output
type ParseConfig struct {
	Type   string            `yaml:"type"` // line-per-result, json, regex
	Schema map[string]Schema `yaml:"schema"`
}

// Schema defines a parsing schema
type Schema struct {
	Regex string `yaml:"regex,omitempty"`
	Group int    `yaml:"group,omitempty"`
	Path  string `yaml:"path,omitempty"` // JSON path
}

// ResourceConfig defines resource requirements
type ResourceConfig struct {
	CPU     string `yaml:"cpu"`     // low, medium, high
	Memory  string `yaml:"memory"`  // low, medium, high
	Network string `yaml:"network"` // none, low, moderate, high
}

// ============================================================================
// BOUNTY PROGRAMS
// ============================================================================

// BountyProgram represents a bug bounty program
type BountyProgram struct {
	ID          string    `json:"id" bson:"_id"`
	Slug        string    `json:"slug" bson:"slug"`                       // e.g., "playtika", "hackerone-xyz"
	Name        string    `json:"name" bson:"name"`                       // e.g., "Playtika Bug Bounty"
	Platform    string    `json:"platform" bson:"platform"`               // hackerone, bugcrowd, intigriti, independent
	URL         string    `json:"url" bson:"url"`                         // Program URL
	Scope       Scope     `json:"scope" bson:"scope"`                     // In-scope / out-of-scope
	PayoutMin   int       `json:"payout_min,omitempty" bson:"payout_min,omitempty"`
	PayoutMax   int       `json:"payout_max,omitempty" bson:"payout_max,omitempty"`
	Rules       []string  `json:"rules,omitempty" bson:"rules,omitempty"` // Special rules / restrictions
	Status      string    `json:"status" bson:"status"`                   // active, paused, completed
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
	LastActive  time.Time `json:"last_active" bson:"last_active"`
	Notes       string    `json:"notes,omitempty" bson:"notes,omitempty"`
}

// ============================================================================
// FINDING & VALIDATION
// ============================================================================

// FindingState represents the state of a finding in the validation pipeline
type FindingState string

const (
	FindingDetected       FindingState = "DETECTED"        // Tool reported something
	FindingVerified       FindingState = "VERIFIED"        // Secondary check confirms
	FindingPoCReady       FindingState = "POC_READY"       // Working exploit generated
	FindingExploited      FindingState = "EXPLOITED"       // PoC executed with evidence
	FindingManualRequired FindingState = "MANUAL_REQUIRED" // Can't auto-verify
	FindingFalsePositive  FindingState = "FALSE_POSITIVE"  // Verification failed
)

// Finding represents a discovered vulnerability
type Finding struct {
	ID             string       `json:"id" bson:"_id"`
	Program        string       `json:"program" bson:"program"`   // bounty program slug
	State          FindingState `json:"state" bson:"state"`
	Title          string       `json:"title" bson:"title"`
	Description    string       `json:"description" bson:"description"`
	Severity       string       `json:"severity" bson:"severity"` // critical, high, medium, low, info
	VulnType       string       `json:"vuln_type" bson:"vuln_type"`
	Target         string       `json:"target" bson:"target"`
	URL            string       `json:"url" bson:"url"`
	Endpoint       string       `json:"endpoint" bson:"endpoint"`
	Parameter      string       `json:"parameter,omitempty" bson:"parameter,omitempty"`
	Method         string       `json:"method,omitempty" bson:"method,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" bson:"headers,omitempty"`
	Payload        string       `json:"payload,omitempty" bson:"payload,omitempty"`
	
	// Detection info
	DetectedBy     string    `json:"detected_by" bson:"detected_by"`
	DetectedAt     time.Time `json:"detected_at" bson:"detected_at"`
	RawOutput      string    `json:"raw_output,omitempty" bson:"raw_output,omitempty"`
	
	// Verification info
	Verification   *Verification `json:"verification,omitempty" bson:"verification,omitempty"`
	VerifiedBy     string    `json:"verified_by,omitempty" bson:"verified_by,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitempty" bson:"verified_at,omitempty"`
	
	// PoC info
	PoC            *PoC      `json:"poc,omitempty" bson:"poc,omitempty"`
	Evidence       []string  `json:"evidence,omitempty" bson:"evidence,omitempty"`
	
	// Manual required info
	ManualReason   string   `json:"manual_reason,omitempty" bson:"manual_reason,omitempty"`
	
	// Classification
	OWASP          string   `json:"owasp,omitempty" bson:"owasp,omitempty"`
	CWE            string   `json:"cwe,omitempty" bson:"cwe,omitempty"`
	CVSSScore      float64  `json:"cvss_score,omitempty" bson:"cvss_score,omitempty"`
	
	// Manual notes
	ManualNotes    string   `json:"manual_notes,omitempty" bson:"manual_notes,omitempty"`
	Tags           []string `json:"tags,omitempty" bson:"tags,omitempty"`
}

// PoC represents a proof of concept
type PoC struct {
	Type           string    `json:"type" bson:"type"` // http, browser, injection, shell
	Description    string    `json:"description,omitempty" bson:"description,omitempty"`
	Request        string    `json:"request,omitempty" bson:"request,omitempty"`
	Payload        string    `json:"payload,omitempty" bson:"payload,omitempty"`
	Steps          []string  `json:"steps,omitempty" bson:"steps,omitempty"`
	CurlCommand    string    `json:"curl_command,omitempty" bson:"curl_command,omitempty"`
	ToolCommand    string    `json:"tool_command,omitempty" bson:"tool_command,omitempty"`
	HTMLPoC        string    `json:"html_poc,omitempty" bson:"html_poc,omitempty"`
	ExpectedResult string    `json:"expected_result,omitempty" bson:"expected_result,omitempty"`
	ActualResult   string    `json:"actual_result,omitempty" bson:"actual_result,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	ExecutedAt     time.Time `json:"executed_at,omitempty" bson:"executed_at,omitempty"`
	Success        bool      `json:"success" bson:"success"`
}

// Verification represents the verification result
type Verification struct {
	Status     string    `json:"status" bson:"status"` // verified, false_positive, manual_required
	Method     string    `json:"method" bson:"method"`
	Confidence float64   `json:"confidence" bson:"confidence"`
	Details    string    `json:"details,omitempty" bson:"details,omitempty"`
	VerifiedAt time.Time `json:"verified_at" bson:"verified_at"`
}

// Evidence represents proof of exploitation
type Evidence struct {
	Type      string    `json:"type" bson:"type"` // screenshot, har, video, log, response
	Path      string    `json:"path" bson:"path"`
	Caption   string    `json:"caption,omitempty" bson:"caption,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}

// ============================================================================
// DECISION LOGGING (MongoDB)
// ============================================================================

// DecisionLog represents a decision made by the LLM
type DecisionLog struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Program   string             `bson:"program"`
	Timestamp time.Time          `bson:"timestamp"`
	SessionID string             `bson:"session_id"`
	Target    string             `bson:"target"`
	
	// What the LLM was thinking
	Context   string `bson:"context"`
	Thinking  string `bson:"thinking"`
	Decision  string `bson:"decision"`
	Reasoning string `bson:"reasoning"`
	
	// What happened
	Action    string `bson:"action"`
	ToolUsed  string `bson:"tool_used,omitempty"`
	ToolArgs  string `bson:"tool_args,omitempty"`
	Result    string `bson:"result"`
	Success   bool   `bson:"success"`
	
	// For learning
	Tags      []string `bson:"tags,omitempty"`
	FindingID string   `bson:"finding_id,omitempty"`
}

// Consultation represents when LLM asked human for help
type Consultation struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Program   string             `bson:"program"`
	Timestamp time.Time          `bson:"timestamp"`
	SessionID string             `bson:"session_id"`
	
	Question  string   `bson:"question"`
	Context   string   `bson:"context"`
	Options   []string `bson:"options,omitempty"`
	Urgency   string   `bson:"urgency"` // blocking, can_continue, fyi
	Category  string   `bson:"category"` // logic, scope, ethics, technical, priority
	
	Response     string    `bson:"response,omitempty"`
	RespondedAt  time.Time `bson:"responded_at,omitempty"`
}

// ============================================================================
// OPSEC
// ============================================================================

// OpsecConfig represents operational security configuration
type OpsecConfig struct {
	Enabled       bool     `yaml:"enabled"`
	ProxyChain    []Proxy  `yaml:"proxy_chain"`
	MACSpoof      bool     `yaml:"mac_spoof"`
	VPNEnabled    bool     `yaml:"vpn_enabled"`
	TorEnabled    bool     `yaml:"tor_enabled"`
	DNSServers    []string `yaml:"dns_servers"`
	CleanEnv      bool     `yaml:"clean_env"`
}

// Proxy represents a proxy in the chain
type Proxy struct {
	Type     string `yaml:"type"` // socks5, http, https
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// OpsecChecklist represents a checklist item for risky operations
type OpsecChecklist struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Steps       []string `yaml:"steps"`
	Verified    bool     `yaml:"verified"`
}

// ============================================================================
// TASK QUEUE
// ============================================================================

// Task represents an async task in the queue
type Task struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // tool_run, fuzzer, crawler, etc.
	Target    string                 `json:"target"`
	Tool      string                 `json:"tool,omitempty"`
	Args      map[string]interface{} `json:"args,omitempty"`
	Status    TaskStatus             `json:"status"`
	Progress  int                    `json:"progress"` // 0-100
	Result    interface{}            `json:"result,omitempty"`
	Error     string                 `json:"error,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	StartedAt time.Time              `json:"started_at,omitempty"`
	EndedAt   time.Time              `json:"ended_at,omitempty"`
}

// TaskStatus represents task status
type TaskStatus string

const (
	TaskPending   TaskStatus = "PENDING"
	TaskRunning   TaskStatus = "RUNNING"
	TaskCompleted TaskStatus = "COMPLETED"
	TaskFailed    TaskStatus = "FAILED"
	TaskCancelled TaskStatus = "CANCELLED"
)

// ============================================================================
// SESSION & STATE
// ============================================================================

// Session represents a testing session
type Session struct {
	ID          string    `json:"id" bson:"_id"`
	Program     string    `json:"program" bson:"program"` // bounty program slug
	Target      string    `json:"target" bson:"target"`
	Scope       Scope     `json:"scope" bson:"scope"`
	StartedAt   time.Time `json:"started_at" bson:"started_at"`
	LastActive  time.Time `json:"last_active" bson:"last_active"`
	Status      string    `json:"status" bson:"status"` // active, paused, completed
	FindingsIDs []string  `json:"findings_ids" bson:"findings_ids"`
}

// Scope represents the testing scope
type Scope struct {
	InScope     []string `json:"in_scope" bson:"in_scope"`
	OutOfScope  []string `json:"out_of_scope" bson:"out_of_scope"`
	VulnTypes   []string `json:"vuln_types,omitempty" bson:"vuln_types,omitempty"`
	Restrictions []string `json:"restrictions,omitempty" bson:"restrictions,omitempty"`
}
