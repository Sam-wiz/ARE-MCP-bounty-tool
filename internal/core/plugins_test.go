package core

import (
	"testing"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

func TestPluginRegistry_NewAndCount(t *testing.T) {
	r := NewPluginRegistry()
	if r == nil {
		t.Fatal("NewPluginRegistry returned nil")
	}
	if r.Count() != 0 {
		t.Errorf("Expected 0 plugins, got %d", r.Count())
	}
}

func TestPluginRegistry_Register(t *testing.T) {
	r := NewPluginRegistry()

	plugin := &types.PluginDefinition{
		Name:     "nmap",
		Category: "recon",
	}

	err := r.Register(plugin)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if r.Count() != 1 {
		t.Errorf("Expected 1, got %d", r.Count())
	}
}

func TestPluginRegistry_RegisterEmpty(t *testing.T) {
	r := NewPluginRegistry()
	err := r.Register(&types.PluginDefinition{})
	if err == nil {
		t.Fatal("Expected error for empty plugin name")
	}
}

func TestPluginRegistry_Get(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "nuclei", Category: "scanner"})

	p, ok := r.Get("nuclei")
	if !ok || p == nil {
		t.Fatal("Get failed for registered plugin")
	}
	if p.Name != "nuclei" {
		t.Errorf("Expected 'nuclei', got %s", p.Name)
	}
}

func TestPluginRegistry_GetNotFound(t *testing.T) {
	r := NewPluginRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("Expected not found")
	}
}

func TestPluginRegistry_GetAll(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "a", Category: "recon"})
	r.Register(&types.PluginDefinition{Name: "b", Category: "scanner"})

	all := r.GetAll()
	if len(all) != 2 {
		t.Errorf("Expected 2, got %d", len(all))
	}
}

func TestPluginRegistry_GetByCategory(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "subfinder", Category: "recon"})
	r.Register(&types.PluginDefinition{Name: "nuclei", Category: "scanner"})
	r.Register(&types.PluginDefinition{Name: "httpx", Category: "recon"})

	recon := r.GetByCategory("recon")
	if len(recon) != 2 {
		t.Errorf("Expected 2 recon plugins, got %d", len(recon))
	}

	scanner := r.GetByCategory("scanner")
	if len(scanner) != 1 {
		t.Errorf("Expected 1 scanner plugin, got %d", len(scanner))
	}

	empty := r.GetByCategory("nonexistent")
	if len(empty) != 0 {
		t.Errorf("Expected 0, got %d", len(empty))
	}
}

func TestPluginRegistry_GetByCapability(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "nmap", Category: "recon", Capabilities: []string{"port-scan", "service-detect"}})
	r.Register(&types.PluginDefinition{Name: "masscan", Category: "recon", Capabilities: []string{"port-scan"}})
	r.Register(&types.PluginDefinition{Name: "nuclei", Category: "scanner", Capabilities: []string{"vuln-scan"}})

	portScanners := r.GetByCapability("port-scan")
	if len(portScanners) != 2 {
		t.Errorf("Expected 2 port-scan plugins, got %d", len(portScanners))
	}
}

func TestPluginRegistry_Unregister(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "temp", Category: "misc"})
	if r.Count() != 1 {
		t.Fatal("Register failed")
	}

	r.Unregister("temp")
	if r.Count() != 0 {
		t.Errorf("Expected 0 after unregister, got %d", r.Count())
	}
}

func TestPluginRegistry_Categories(t *testing.T) {
	r := NewPluginRegistry()
	r.Register(&types.PluginDefinition{Name: "a", Category: "recon"})
	r.Register(&types.PluginDefinition{Name: "b", Category: "scanner"})
	r.Register(&types.PluginDefinition{Name: "c", Category: "recon"})

	cats := r.Categories()
	if len(cats) != 2 {
		t.Errorf("Expected 2 categories, got %d", len(cats))
	}
}
