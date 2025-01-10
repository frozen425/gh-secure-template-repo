package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// Logger provides structured logging with debug support
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// SecuritySettingsRegistry manages all security settings
type SecuritySettingsRegistry struct {
	settings map[string]SecuritySettingManager
	logger   Logger
}

// NewSecuritySettingsRegistry creates a new registry instance
func NewSecuritySettingsRegistry(logger Logger) *SecuritySettingsRegistry {
	registry := &SecuritySettingsRegistry{
		settings: make(map[string]SecuritySettingManager),
		logger:   logger,
	}

	logger.Debug("Created new SecuritySettingsRegistry")
	return registry
}

// RegisterSetting adds a security setting manager to the registry
func (r *SecuritySettingsRegistry) RegisterSetting(name string, manager SecuritySettingManager) {
	r.settings[name] = manager
	r.logger.Debug("Registered security setting: %s - %s", name, manager.GetSetting().Description)
}

// GetManager retrieves a security setting manager by name
func (r *SecuritySettingsRegistry) GetManager(name string) (SecuritySettingManager, bool) {
	manager, exists := r.settings[name]
	return manager, exists
}

// GetValue retrieves the current value of a security setting
func (r *SecuritySettingsRegistry) GetValue(ctx context.Context, name string, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	if manager, exists := r.GetManager(name); exists {
		return manager.GetValue(ctx, client, config, info)
	}
	return SecuritySettingValue{
		Enabled: false,
		Error:   fmt.Errorf("security setting not found: %s", name),
	}
}

// GetAllValues retrieves the current values of all registered security settings
func (r *SecuritySettingsRegistry) GetAllValues(ctx context.Context, client *github.Client, config Config, info *RepoInfo) map[string]SecuritySettingValue {
	values := make(map[string]SecuritySettingValue)
	for name, manager := range r.settings {
		values[name] = manager.GetValue(ctx, client, config, info)
	}
	return values
}

// DebugPrintSettings prints all settings and their values if debug mode is enabled
func (r *SecuritySettingsRegistry) DebugPrintSettings(ctx context.Context, client *github.Client, config Config, info *RepoInfo) {
	r.logger.Debug("Security Settings Registry Contents:")
	r.logger.Debug("Total registered settings: %d", len(r.settings))

	for name, manager := range r.settings {
		setting := manager.GetSetting()
		value := manager.GetValue(ctx, client, config, info)

		r.logger.Debug("Setting: %s", name)
		r.logger.Debug("  Description: %s", setting.Description)
		r.logger.Debug("  Type: %v", setting.Type)
		r.logger.Debug("  Visibility: %v", setting.Visibility)
		r.logger.Debug("  Plan: %v", setting.Plan)
		r.logger.Debug("  Enabled: %v", value.Enabled)
		if value.Error != nil {
			r.logger.Debug("  Error: %v", value.Error)
		}
		if value.Value != nil {
			r.logger.Debug("  Value: %+v", value.Value)
		}
		r.logger.Debug("  Available: %v", setting.IsAvailable(info))
		r.logger.Debug("---")
	}
}
