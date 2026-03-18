package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// EvidenceCollector captures proof of exploitation
type EvidenceCollector struct {
	baseDir string
}

// HAREntry represents an HTTP Archive entry
type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
}

// HARRequest represents a HAR request
type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARQuery  `json:"queryString"`
	PostData    *HARPost    `json:"postData,omitempty"`
}

// HARResponse represents a HAR response
type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
}

// HARHeader represents a header in HAR format
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARQuery represents a query parameter
type HARQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPost represents POST data
type HARPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARContent represents response content
type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HAR represents a complete HTTP Archive
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog is the container for HAR entries
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

// HARCreator identifies what created the HAR
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// NewEvidenceCollector creates a new evidence collector
func NewEvidenceCollector(baseDir string) *EvidenceCollector {
	if baseDir == "" {
		baseDir = "/tmp/hack-ai-v2/evidence"
	}
	os.MkdirAll(baseDir, 0755)
	return &EvidenceCollector{baseDir: baseDir}
}

// CaptureScreenshot captures a screenshot of a URL
func (e *EvidenceCollector) CaptureScreenshot(ctx context.Context, targetURL string) (string, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return "", fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage(targetURL)
	defer page.MustClose()

	// Wait for page to load
	page.MustWaitLoad()
	time.Sleep(1 * time.Second) // Allow dynamic content to render

	// Generate filename
	filename := filepath.Join(e.baseDir, fmt.Sprintf("screenshot_%d.png", time.Now().UnixNano()))

	// Capture full page screenshot
	page.MustScreenshotFullPage(filename)

	return filename, nil
}

// CaptureHAR captures HTTP traffic as HAR format
func (e *EvidenceCollector) CaptureHAR(ctx context.Context, targetURL string) (string, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return "", fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage("")

	// Enable network monitoring
	router := page.HijackRequests()
	
	entries := make([]HAREntry, 0)
	
	router.MustAdd("*", func(ctx *rod.Hijack) {
		start := time.Now()
		ctx.MustLoadResponse()
		
		entry := HAREntry{
			StartedDateTime: start.Format(time.RFC3339),
			Time:            time.Since(start).Seconds() * 1000,
			Request: HARRequest{
				Method:      ctx.Request.Method(),
				URL:         ctx.Request.URL().String(),
				HTTPVersion: "HTTP/1.1",
				Headers:     convertRodHeaders(ctx.Request.Headers()),
			},
			Response: HARResponse{
				Status:      ctx.Response.Payload().ResponseCode,
				StatusText:  "",
				HTTPVersion: "HTTP/1.1",
				Headers:     convertHTTPHeaders(ctx.Response.Headers()),
				Content: HARContent{
					Size:     len(ctx.Response.Body()),
					MimeType: ctx.Response.Headers().Get("Content-Type"),
					Text:     string(ctx.Response.Body()),
				},
			},
		}
		entries = append(entries, entry)
	})

	go router.Run()

	// Navigate to target
	page.MustNavigate(targetURL)
	page.MustWaitLoad()
	time.Sleep(2 * time.Second) // Capture async requests

	router.Stop()

	// Build HAR
	har := HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "hack-ai-v2",
				Version: "2.0.0",
			},
			Entries: entries,
		},
	}

	// Save HAR
	filename := filepath.Join(e.baseDir, fmt.Sprintf("capture_%d.har", time.Now().UnixNano()))
	data, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// CaptureVideo records a video of the exploitation
func (e *EvidenceCollector) CaptureVideo(ctx context.Context, targetURL string, actions func(*rod.Page) error) (string, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return "", fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage(targetURL)
	defer page.MustClose()

	// Start screen capture
	_ = filepath.Join(e.baseDir, fmt.Sprintf("video_%d.webm", time.Now().UnixNano()))
	
	// Note: Rod doesn't have built-in video recording
	// This would typically use CDP's screencast feature
	// For now, we'll capture a series of screenshots as frames
	
	framesDir := filepath.Join(e.baseDir, fmt.Sprintf("frames_%d", time.Now().UnixNano()))
	os.MkdirAll(framesDir, 0755)
	
	// Start frame capture goroutine
	done := make(chan bool)
	frameCount := 0
	
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond) // 5 FPS
		defer ticker.Stop()
		
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				framePath := filepath.Join(framesDir, fmt.Sprintf("frame_%04d.png", frameCount))
				page.MustScreenshot(framePath)
				frameCount++
			}
		}
	}()

	// Execute the actions
	if actions != nil {
		if err := actions(page); err != nil {
			done <- true
			return "", err
		}
	} else {
		// Default: wait and capture
		time.Sleep(5 * time.Second)
	}
	
	done <- true

	// Convert frames to video would require ffmpeg
	// For now, return the frames directory
	return framesDir, nil
}

// CaptureResponse captures raw HTTP response
func (e *EvidenceCollector) CaptureResponse(ctx context.Context, targetURL string, method string, headers map[string]string, body string) (string, error) {
	// Create response capture file
	filename := filepath.Join(e.baseDir, fmt.Sprintf("response_%d.txt", time.Now().UnixNano()))

	content := fmt.Sprintf("=== REQUEST ===\n%s %s\n\n", method, targetURL)
	content += "Headers:\n"
	for k, v := range headers {
		content += fmt.Sprintf("  %s: %s\n", k, v)
	}
	if body != "" {
		content += fmt.Sprintf("\nBody:\n%s\n", body)
	}

	content += "\n=== RESPONSE ===\n"
	// Would add actual response here from HTTP client

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// CaptureDOM captures the current DOM state
func (e *EvidenceCollector) CaptureDOM(ctx context.Context, targetURL string) (string, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return "", fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage(targetURL)
	defer page.MustClose()

	page.MustWaitLoad()

	// Get full HTML
	html := page.MustHTML()

	filename := filepath.Join(e.baseDir, fmt.Sprintf("dom_%d.html", time.Now().UnixNano()))
	if err := os.WriteFile(filename, []byte(html), 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// CaptureConsole captures browser console output
func (e *EvidenceCollector) CaptureConsole(ctx context.Context, targetURL string, duration time.Duration) (string, error) {
	browser, err := e.launchBrowser()
	if err != nil {
		return "", fmt.Errorf("failed to launch browser: %w", err)
	}
	defer browser.MustClose()

	page := browser.MustPage("")
	defer page.MustClose()

	// Collect console messages
	var consoleLogs []string

	go page.EachEvent(func(e *proto.RuntimeConsoleAPICalled) {
		for _, arg := range e.Args {
			if arg.Value.Str() != "" {
				consoleLogs = append(consoleLogs, fmt.Sprintf("[%s] %v", e.Type, arg.Value))
			}
		}
	})()

	page.MustNavigate(targetURL)
	page.MustWaitLoad()
	time.Sleep(duration)

	// Save console log
	filename := filepath.Join(e.baseDir, fmt.Sprintf("console_%d.log", time.Now().UnixNano()))
	content := ""
	for _, log := range consoleLogs {
		content += log + "\n"
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// launchBrowser starts a headless browser
func (e *EvidenceCollector) launchBrowser() (*rod.Browser, error) {
	path, exists := launcher.LookPath()
	if !exists {
		return nil, fmt.Errorf("Chrome/Chromium not found")
	}

	u := launcher.New().
		Bin(path).
		Headless(true).
		MustLaunch()

	browser := rod.New().ControlURL(u).MustConnect()
	return browser, nil
}

// Helper functions
func convertRodHeaders(headers proto.NetworkHeaders) []HARHeader {
	result := make([]HARHeader, 0)
	for k, v := range headers {
		result = append(result, HARHeader{Name: k, Value: fmt.Sprintf("%v", v)})
	}
	return result
}

func convertHTTPHeaders(headers interface{}) []HARHeader {
	result := make([]HARHeader, 0)
	switch h := headers.(type) {
	case map[string][]string:
		for k, v := range h {
			for _, val := range v {
				result = append(result, HARHeader{Name: k, Value: val})
			}
		}
	case proto.NetworkHeaders:
		for k, v := range h {
			result = append(result, HARHeader{Name: k, Value: fmt.Sprintf("%v", v)})
		}
	}
	return result
}
