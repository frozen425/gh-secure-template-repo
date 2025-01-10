package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// SignedCommitsManager implements SecuritySettingManager for signed commits
type SignedCommitsManager struct {
	setting SecuritySetting
}

// NewSignedCommitsManager creates a new manager for signed commits setting
func NewSignedCommitsManager() *SignedCommitsManager {
	return &SignedCommitsManager{
		setting: SecuritySetting{
			Name:        "signed_commits",
			Description: "Requires all commits to be signed with GPG keys",
			Type:        SecurityTypeBranchProtection,
			Visibility:  VisibilityAny,
			Plan:        PlanAny,
			IsAvailable: func(info *RepoInfo) bool {
				return true
			},
		},
	}
}

// GetSetting returns the SecuritySetting metadata
func (m *SignedCommitsManager) GetSetting() SecuritySetting {
	return m.setting
}

// GetValue gets the current value/state of the security setting
func (m *SignedCommitsManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	if !m.setting.IsAvailable(info) {
		return SecuritySettingValue{
			Enabled: false,
			Error:   fmt.Errorf("signed commits not available for this repository"),
		}
	}

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{
			Enabled: false,
			Error:   fmt.Errorf("error checking signed commits: %w", err),
		}
	}

	setting := protection.GetRequiredSignatures()
	return SecuritySettingValue{
		Enabled: setting.GetEnabled(),
		Value: map[string]interface{}{
			"branch": info.DefaultBranch,
		},
	}
}

// Enable enables the security setting
func (m *SignedCommitsManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	if !m.setting.IsAvailable(info) {
		return fmt.Errorf("signed commits not available for this repository")
	}

	_, _, err := client.Repositories.RequireSignaturesOnProtectedBranch(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}

// Disable disables the security setting
func (m *SignedCommitsManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	if !m.setting.IsAvailable(info) {
		return fmt.Errorf("signed commits not available for this repository")
	}

	_, err := client.Repositories.OptionalSignaturesOnProtectedBranch(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}
