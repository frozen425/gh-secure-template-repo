package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// RequireStatusChecksManager checks whether the default branch requires
// status checks to pass before merging.
type RequireStatusChecksManager struct {
	setting SecuritySetting
}

func NewRequireStatusChecksManager() *RequireStatusChecksManager {
	return &RequireStatusChecksManager{
		setting: SecuritySetting{
			Name:           "require_status_checks",
			Description:    "Status checks must pass before merging",
			Type:           SecurityTypeBranchProtection,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityHigh,
			RequiredScopes: []string{"repo"},
			IsAvailable: func(info *RepoInfo) (bool, string) {
				return true, ""
			},
		},
	}
}

func (m *RequireStatusChecksManager) GetSetting() SecuritySetting { return m.setting }

func (m *RequireStatusChecksManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking status checks: %w", err)}
	}

	checks := protection.GetRequiredStatusChecks()
	if checks == nil {
		return SecuritySettingValue{Enabled: false}
	}

	// If the user specified required check contexts, verify they are all present.
	missingContexts := []string{}
	if len(config.RequiredChecks) > 0 && checks.Contexts != nil {
		existing := map[string]bool{}
		for _, c := range *checks.Contexts {
			existing[c] = true
		}
		for _, req := range config.RequiredChecks {
			if !existing[req] {
				missingContexts = append(missingContexts, req)
			}
		}
	}

	enabled := checks.Strict && len(missingContexts) == 0
	return SecuritySettingValue{
		Enabled: enabled,
		Value: map[string]interface{}{
			"strict":           checks.Strict,
			"contexts":         checks.Contexts,
			"missing_contexts": missingContexts,
		},
	}
}

func (m *RequireStatusChecksManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	req := &github.RequiredStatusChecksRequest{
		Strict: github.Ptr(true),
	}
	// If the user specified required check contexts, configure them.
	if len(config.RequiredChecks) > 0 {
		checks := make([]*github.RequiredStatusCheck, len(config.RequiredChecks))
		for i, c := range config.RequiredChecks {
			checks[i] = &github.RequiredStatusCheck{Context: c}
		}
		req.Checks = checks
	}
	_, resp, err := client.Repositories.UpdateRequiredStatusChecks(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	if err != nil && resp != nil && resp.StatusCode == 404 {
		// Status checks not yet enabled — add them via branch protection update.
		protection, _, getErr := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
		if getErr != nil {
			return fmt.Errorf("cannot read existing protection to add status checks: %w", getErr)
		}
		pReq := protectionToRequest(protection)
		checks := req.Checks
		if checks == nil {
			checks = make([]*github.RequiredStatusCheck, 0)
		}
		pReq.RequiredStatusChecks = &github.RequiredStatusChecks{
			Strict: true,
			Checks: &checks,
		}
		_, _, err = client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, pReq)
	}
	return err
}

func (m *RequireStatusChecksManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, err := client.Repositories.RemoveRequiredStatusChecks(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}
