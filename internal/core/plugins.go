package core

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/samrudh/hack-ai-v2/internal/types"
)

// PluginRegistry manages loaded plugins
type PluginRegistry struct {
	plugins map[string]*types.PluginDefinition
	mu      sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]*types.PluginDefinition),
	}
}

// LoadPlugins loads all plugins from a directory
func (r *PluginRegistry) LoadPlugins(baseDir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Load core plugins
	coreDir := filepath.Join(baseDir, "core")
	if err := r.loadFromDir(coreDir); err != nil {
		log.Printf("Warning: Failed to load core plugins: %v", err)
	}

	// Load custom plugins
	customDir := filepath.Join(baseDir, "custom")
	if err := r.loadFromDir(customDir); err != nil {
		log.Printf("Warning: Failed to load custom plugins: %v", err)
	}

	log.Printf("Loaded %d plugins", len(r.plugins))
	return nil
}

// loadFromDir loads plugins from a directory recursively
func (r *PluginRegistry) loadFromDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		if info.IsDir() {
			return nil
		}

		// Only load .yaml files
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		plugin, err := r.loadPlugin(path)
		if err != nil {
			log.Printf("Warning: Failed to load plugin %s: %v", path, err)
			return nil
		}

		r.plugins[plugin.Name] = plugin
		log.Printf("Loaded plugin: %s (%s)", plugin.Name, plugin.Category)
		return nil
	})
}

// loadPlugin loads a single plugin from a YAML file
func (r *PluginRegistry) loadPlugin(path string) (*types.PluginDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var plugin types.PluginDefinition
	if err := yaml.Unmarshal(data, &plugin); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if plugin.Name == "" {
		return nil, fmt.Errorf("plugin name is required")
	}

	return &plugin, nil
}

// Get retrieves a plugin by name
func (r *PluginRegistry) Get(name string) (*types.PluginDefinition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, ok := r.plugins[name]
	return plugin, ok
}

// GetAll returns all loaded plugins
func (r *PluginRegistry) GetAll() []*types.PluginDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]*types.PluginDefinition, 0, len(r.plugins))
	for _, p := range r.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// GetByCategory returns plugins in a specific category
func (r *PluginRegistry) GetByCategory(category string) []*types.PluginDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]*types.PluginDefinition, 0)
	for _, p := range r.plugins {
		if p.Category == category {
			plugins = append(plugins, p)
		}
	}
	return plugins
}

// GetByCapability returns plugins with a specific capability
func (r *PluginRegistry) GetByCapability(capability string) []*types.PluginDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]*types.PluginDefinition, 0)
	for _, p := range r.plugins {
		for _, cap := range p.Capabilities {
			if cap == capability {
				plugins = append(plugins, p)
				break
			}
		}
	}
	return plugins
}

// Register adds a plugin to the registry
func (r *PluginRegistry) Register(plugin *types.PluginDefinition) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	r.plugins[plugin.Name] = plugin
	return nil
}

// Unregister removes a plugin from the registry
func (r *PluginRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.plugins, name)
}

// Count returns the number of loaded plugins
func (r *PluginRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}

// Categories returns all unique categories
func (r *PluginRegistry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categorySet := make(map[string]struct{})
	for _, p := range r.plugins {
		categorySet[p.Category] = struct{}{}
	}

	categories := make([]string, 0, len(categorySet))
	for cat := range categorySet {
		categories = append(categories, cat)
	}
	return categories
}
