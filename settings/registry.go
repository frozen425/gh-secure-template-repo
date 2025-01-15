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

// ApplySettings applies all registered security settings
func (r *SecuritySettingsRegistry) ApplySettings(ctx context.Context, client *github.Client, config Config, info *RepoInfo) {
	if config.DryRun {
		r.logger.Info("[DRY RUN] Would apply security settings")
		return
	}

	// First enable repository settings
	if repoManager, exists := r.settings["repository_settings"]; exists {
		value := repoManager.GetValue(ctx, client, config, info)
		if !value.Enabled {
			r.logger.Info("Enabling setting: [repository_settings]")
			if err := repoManager.Enable(ctx, client, config, info); err != nil {
				r.logger.Error("Failed to enable setting: [repository_settings] resulted in error: %v", err)
			}
		} else {
			r.logger.Debug("Setting repository_settings already enabled")
		}
	}

	// Then enable branch protection
	if branchManager, exists := r.settings["branch_protection"]; exists {
		value := branchManager.GetValue(ctx, client, config, info)
		if !value.Enabled {
			r.logger.Info("Enabling setting: [branch_protection]")
			if err := branchManager.Enable(ctx, client, config, info); err != nil {
				r.logger.Error("Failed to enable setting: [branch_protection] resulted in error: %v", err)
			}
		} else {
			r.logger.Debug("Setting branch_protection already enabled")
		}
	}

	// Finally enable signed commits (requires branch protection)
	if signedManager, exists := r.settings["signed_commits"]; exists {
		value := signedManager.GetValue(ctx, client, config, info)
		if !value.Enabled {
			// Check if branch protection is enabled first
			if branchManager, exists := r.settings["branch_protection"]; exists {
				branchValue := branchManager.GetValue(ctx, client, config, info)
				if branchValue.Enabled {
					r.logger.Info("Enabling setting: [signed_commits]")
					if err := signedManager.Enable(ctx, client, config, info); err != nil {
						r.logger.Error("Failed to enable setting: [signed_commits] resulted in error: %v", err)
					}
				} else {
					r.logger.Debug("Skipping signed_commits as branch_protection is not enabled")
				}
			}
		} else {
			r.logger.Debug("Setting signed_commits already enabled")
		}
	}

	// Enable any remaining settings
	for name, manager := range r.settings {
		if name == "repository_settings" || name == "branch_protection" || name == "signed_commits" {
			continue // Already handled above
		}

		if !manager.GetSetting().IsAvailable(info) {
			r.logger.Debug("Setting %s not available for this repository", name)
			continue
		}

		value := manager.GetValue(ctx, client, config, info)
		if value.Enabled {
			r.logger.Debug("Setting %s already enabled", name)
		} else {
			r.logger.Info("Enabling setting: [%s]", name)
			if err := manager.Enable(ctx, client, config, info); err != nil {
				r.logger.Error("Failed to enable setting: [%s] resulted in error: %v", name, err)
			}
		}
	}
}

// DisableAll disables all registered security settings
func (r *SecuritySettingsRegistry) DisableAll(ctx context.Context, client *github.Client, config Config, info *RepoInfo) {
	for name, manager := range r.settings {
		if !manager.GetSetting().IsAvailable(info) {
			r.logger.Debug("Setting %s not available for this repository", name)
			continue
		}

		// Check if setting is enabled
		value := manager.GetValue(ctx, client, config, info)
		if !value.Enabled {
			r.logger.Debug("Setting %s already disabled", name)
			continue
		}

		// Disable the setting
		r.logger.Info("Disabling setting: [%s]", name)
		if err := manager.Disable(ctx, client, config, info); err != nil {
			r.logger.Error("Failed to disable setting: [%s] resulted in error: %v", name, err)
		}
	}
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
