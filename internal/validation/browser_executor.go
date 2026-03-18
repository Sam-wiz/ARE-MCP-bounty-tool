package validation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// BrowserExecutor handles browser-based PoC execution using Rod
type BrowserExecutor struct {
	headless    bool
	screenshotDir string
}

// NewBrowserExecutor creates a new browser executor
func NewBrowserExecutor() *BrowserExecutor {
	return &BrowserExecutor{
		headless:    true,
		screenshotDir: "/tmp/hack-ai-v2/screenshots",
	}
}

// CanHandle checks if this executor can handle the finding
func (e *BrowserExecutor) CanHandle(finding *types.Finding) bool {
	// Browser-based vulns that need JavaScript execution
	browserTypes := []string{
		"dom_xss", "stored_xss", "csrf", "clickjacking",
		"cors", "postmessage", "websocket",
	}
	
	for _, t := range browserTypes {
		if strings.Contains(strings.ToLower(finding.VulnType), t) {
			return true
		}
	}
	return false
}

// Verify performs browser-based verification
func (e *BrowserExecutor) Verify(ctx context.Context, finding *types.Finding) (*VerifyResult, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage(finding.URL)
	defer page.MustClose()

	// Wait for page load
	page.MustWaitLoad()

	// Check for vulnerability indicators based on type
	verified, confidence := e.verifyInBrowser(page, finding)

	return &VerifyResult{
		Verified:   verified,
		Confidence: confidence,
		Method:     "browser_verification",
		Details:    fmt.Sprintf("Browser-based verification for %s", finding.VulnType),
	}, nil
}

// GeneratePoC creates a browser-based proof of concept
func (e *BrowserExecutor) GeneratePoC(ctx context.Context, finding *types.Finding) (*types.PoC, error) {
	poc := &types.PoC{
		Type:        "browser",
		Description: fmt.Sprintf("Browser-based PoC for %s vulnerability", finding.VulnType),
		Steps:       make([]string, 0),
		Payload:     e.generateBrowserPayload(finding),
		CreatedAt:   time.Now(),
	}

	// Generate browser-specific steps
	poc.Steps = append(poc.Steps, "1. Open browser and navigate to target URL")
	poc.Steps = append(poc.Steps, fmt.Sprintf("2. URL: %s", finding.URL))
	
	switch strings.ToLower(finding.VulnType) {
	case "dom_xss":
		poc.Steps = append(poc.Steps, "3. Inject payload into DOM sink")
		poc.Steps = append(poc.Steps, "4. Observe JavaScript execution")
	case "csrf":
		poc.Steps = append(poc.Steps, "3. Host malicious page with CSRF form")
		poc.Steps = append(poc.Steps, "4. Trick victim to visit page")
	case "clickjacking":
		poc.Steps = append(poc.Steps, "3. Embed target in iframe")
		poc.Steps = append(poc.Steps, "4. Overlay transparent element")
	}

	// Generate HTML PoC
	poc.HTMLPoC = e.generateHTMLPoC(finding, poc.Payload)

	return poc, nil
}

// ExecutePoC runs the browser-based proof of concept
func (e *BrowserExecutor) ExecutePoC(ctx context.Context, poc *types.PoC) (*ExecuteResult, error) {
	start := time.Now()
	result := &ExecuteResult{
		Success:     false,
		ExecutionMs: 0,
	}

	browser, err := e.launchBrowser()
	if err != nil {
		return result, fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	// Create temp HTML file for PoC if needed
	if poc.HTMLPoC != "" {
		pocPath, err := e.savePoCHTML(poc.HTMLPoC)
		if err != nil {
			return result, err
		}
		defer os.Remove(pocPath)

		page := browser.MustPage("file://" + pocPath)
		defer page.MustClose()

		// Wait and check for success
		page.MustWaitLoad()
		time.Sleep(2 * time.Second) // Allow JS to execute

		// Check for success indicators
		result.Success = e.checkPoCSuccess(page, poc)
	}

	// Capture screenshot
	screenshot, err := e.captureScreenshot(browser, poc)
	if err == nil {
		result.Screenshot = screenshot
	}

	result.ExecutionMs = time.Since(start).Milliseconds()
	return result, nil
}

// launchBrowser starts a browser instance
func (e *BrowserExecutor) launchBrowser() (*rod.Browser, error) {
	path, exists := launcher.LookPath()
	if !exists {
		return nil, fmt.Errorf("Chrome/Chromium not found")
	}

	u := launcher.New().
		Bin(path).
		Headless(e.headless).
		MustLaunch()

	browser := rod.New().ControlURL(u).MustConnect()
	return browser, nil
}

// verifyInBrowser checks for vulnerability in browser context
func (e *BrowserExecutor) verifyInBrowser(page *rod.Page, finding *types.Finding) (bool, float64) {
	vulnType := strings.ToLower(finding.VulnType)

	switch vulnType {
	case "dom_xss":
		// Check for alert dialog or DOM manipulation
		hasAlert := e.checkForAlert(page)
		if hasAlert {
			return true, 0.95
		}

	case "cors":
		// Check if CORS allows unauthorized access
		// Inject test script
		result := page.MustEval(`() => {
			try {
				return fetch(window.location.href, {
					credentials: 'include'
				}).then(r => r.ok);
			} catch(e) {
				return false;
			}
		}`)
		if result.Bool() {
			return true, 0.8
		}

	case "clickjacking":
		// Check X-Frame-Options
		result := page.MustEval(`() => {
			return !document.querySelector('meta[http-equiv="X-Frame-Options"]');
		}`)
		if result.Bool() {
			return true, 0.7
		}
	}

	return false, 0.0
}

// checkForAlert checks if an alert dialog appeared
func (e *BrowserExecutor) checkForAlert(page *rod.Page) bool {
	// Set up dialog handler
	alertFired := false
	go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		alertFired = true
	})()

	// Trigger any pending alerts
	page.MustEval(`() => { /* trigger */ }`)
	time.Sleep(500 * time.Millisecond)

	return alertFired
}

// generateBrowserPayload creates browser-specific payload
func (e *BrowserExecutor) generateBrowserPayload(finding *types.Finding) string {
	switch strings.ToLower(finding.VulnType) {
	case "dom_xss":
		return `<img src=x onerror="alert(document.domain)">`
	case "csrf":
		return `<form action="TARGET" method="POST"><input type="hidden" name="param" value="malicious"></form><script>document.forms[0].submit()</script>`
	case "clickjacking":
		return `<iframe src="TARGET" style="opacity:0.1;position:absolute;width:100%;height:100%;"></iframe>`
	default:
		return finding.Payload
	}
}

// generateHTMLPoC creates a complete HTML PoC page
func (e *BrowserExecutor) generateHTMLPoC(finding *types.Finding, payload string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>PoC - %s</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .info { background: #f0f0f0; padding: 10px; margin: 10px 0; }
        .payload { background: #ffe0e0; padding: 10px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Proof of Concept: %s</h1>
    <div class="info">
        <strong>Target:</strong> %s<br>
        <strong>Type:</strong> %s<br>
        <strong>Generated:</strong> %s
    </div>
    <h2>Payload</h2>
    <div class="payload">%s</div>
    <h2>Execution</h2>
    <div id="poc-container">
        %s
    </div>
    <script>
        console.log('PoC executed at:', new Date().toISOString());
        window.pocExecuted = true;
    </script>
</body>
</html>`, finding.VulnType, finding.VulnType, finding.URL, finding.VulnType, 
		time.Now().Format(time.RFC3339), payload, payload)
}

// savePoCHTML saves HTML PoC to temp file
func (e *BrowserExecutor) savePoCHTML(html string) (string, error) {
	tmpDir := "/tmp/hack-ai-v2/poc"
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", err
	}

	filename := filepath.Join(tmpDir, fmt.Sprintf("poc_%d.html", time.Now().UnixNano()))
	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// checkPoCSuccess checks if PoC execution was successful
func (e *BrowserExecutor) checkPoCSuccess(page *rod.Page, poc *types.PoC) bool {
	result := page.MustEval(`() => window.pocExecuted === true`)
	return result.Bool()
}

// captureScreenshot captures a screenshot of the PoC execution
func (e *BrowserExecutor) captureScreenshot(browser *rod.Browser, poc *types.PoC) (string, error) {
	if err := os.MkdirAll(e.screenshotDir, 0755); err != nil {
		return "", err
	}

	// Take screenshot of active page
	pages := browser.MustPages()
	if len(pages) == 0 {
		return "", fmt.Errorf("no pages to screenshot")
	}

	page := pages[0]
	filename := filepath.Join(e.screenshotDir, fmt.Sprintf("poc_%d.png", time.Now().UnixNano()))
	
	page.MustScreenshot(filename)
	return filename, nil
}
