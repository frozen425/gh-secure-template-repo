package settings

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-github/v68/github"

	applog "gh-secure-template-repo/internal/log"
)

// SecuritySettingsRegistry manages all security settings.
type SecuritySettingsRegistry struct {
	settings map[string]SecuritySettingManager
	order    []string // insertion order for deterministic output
	logger   applog.Logger
	token    *TokenCapabilities
}

// NewSecuritySettingsRegistry creates a new registry instance.
func NewSecuritySettingsRegistry(logger applog.Logger, token *TokenCapabilities) *SecuritySettingsRegistry {
	registry := &SecuritySettingsRegistry{
		settings: make(map[string]SecuritySettingManager),
		logger:   logger,
		token:    token,
	}
	logger.Debug("Created new SecuritySettingsRegistry")
	return registry
}

// RegisterSetting adds a security setting manager to the registry.
func (r *SecuritySettingsRegistry) RegisterSetting(name string, manager SecuritySettingManager) {
	r.settings[name] = manager
	r.order = append(r.order, name)
	r.logger.Debug("Registered security setting: %s - %s", name, manager.GetSetting().Description)
}

// GetManager retrieves a security setting manager by name.
func (r *SecuritySettingsRegistry) GetManager(name string) (SecuritySettingManager, bool) {
	manager, exists := r.settings[name]
	return manager, exists
}

// GetValue retrieves the current value of a security setting.
func (r *SecuritySettingsRegistry) GetValue(ctx context.Context, name string, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	if manager, exists := r.GetManager(name); exists {
		return manager.GetValue(ctx, client, config, info)
	}
	return SecuritySettingValue{
		Enabled: false,
		Error:   fmt.Errorf("security setting not found: %s", name),
	}
}

// AssessAll evaluates every registered setting concurrently and returns
// results in registration order.
func (r *SecuritySettingsRegistry) AssessAll(ctx context.Context, client *github.Client, config Config, info *RepoInfo) []AssessmentResult {
	type indexedResult struct {
		idx    int
		result AssessmentResult
	}

	results := make([]AssessmentResult, len(r.order))
	ch := make(chan indexedResult, len(r.order))

	var wg sync.WaitGroup
	for i, name := range r.order {
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			ch <- indexedResult{idx: idx, result: r.assessOne(ctx, client, config, info, n)}
		}(i, name)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for ir := range ch {
		results[ir.idx] = ir.result
	}
	return results
}

// assessOne evaluates a single setting, handling scope-gating and availability.
func (r *SecuritySettingsRegistry) assessOne(ctx context.Context, client *github.Client, config Config, info *RepoInfo, name string) AssessmentResult {
	manager, exists := r.settings[name]
	if !exists {
		return AssessmentResult{
			Name:   name,
			Status: StatusError,
			Detail: "setting not registered",
		}
	}

	setting := manager.GetSetting()
	base := AssessmentResult{
		Name:        setting.Name,
		Description: setting.Description,
		Severity:    setting.Severity,
	}

	// Check token scopes.
	if r.token != nil {
		for _, scope := range setting.RequiredScopes {
			if !r.token.HasScope(scope) {
				base.Status = StatusSkipped
				base.Detail = fmt.Sprintf("token missing required scope: %s", scope)
				return base
			}
		}
	}

	// Check availability (plan / visibility gating).
	avail, reason := setting.IsAvailable(info)
	if !avail {
		base.Status = StatusSkipped
		base.Detail = reason
		return base
	}

	value := manager.GetValue(ctx, client, config, info)
	if value.Error != nil {
		base.Status = StatusError
		base.Detail = value.Error.Error()
		return base
	}

	if value.Enabled {
		base.Status = StatusPass
		base.Detail = "enabled"
	} else {
		base.Status = StatusFail
		base.Detail = "not enabled"
	}
	return base
}

// ApplyAll enables all checks that are currently failing.
// Returns the list of results after attempting remediation.
func (r *SecuritySettingsRegistry) ApplyAll(ctx context.Context, client *github.Client, config Config, info *RepoInfo) []AssessmentResult {
	results := r.AssessAll(ctx, client, config, info)
	for i, res := range results {
		if res.Status != StatusFail {
			continue
		}
		manager, _ := r.settings[res.Name]
		if err := manager.Enable(ctx, client, config, info); err != nil {
			results[i].Detail = fmt.Sprintf("remediation failed: %v", err)
			results[i].Status = StatusError
		} else {
			results[i].Detail = "remediated"
			results[i].Status = StatusPass
		}
	}
	return results
}

// DebugPrintSettings prints all settings and their values (legacy helper).
func (r *SecuritySettingsRegistry) DebugPrintSettings(ctx context.Context, client *github.Client, config Config, info *RepoInfo) {
	r.logger.Debug("Security Settings Registry Contents:")
	r.logger.Debug("Total registered settings: %d", len(r.settings))

	for _, name := range r.order {
		manager := r.settings[name]
		setting := manager.GetSetting()
		value := manager.GetValue(ctx, client, config, info)

		r.logger.Debug("Setting: %s", name)
		r.logger.Debug("  Description: %s", setting.Description)
		r.logger.Debug("  Type: %v", setting.Type)
		r.logger.Debug("  Visibility: %v", setting.Visibility)
		r.logger.Debug("  Plan: %v", setting.Plan)
		r.logger.Debug("  Severity: %v", setting.Severity)
		r.logger.Debug("  Enabled: %v", value.Enabled)
		if value.Error != nil {
			r.logger.Debug("  Error: %v", value.Error)
		}
		if value.Value != nil {
			r.logger.Debug("  Value: %+v", value.Value)
		}
		avail, reason := setting.IsAvailable(info)
		r.logger.Debug("  Available: %v (%s)", avail, reason)
		r.logger.Debug("---")
	}
}
