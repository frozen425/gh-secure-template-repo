package settings

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v68/github"
)

// SignedCommitsManager manages signed commits settings
type SignedCommitsManager struct {
	setting SecuritySetting
	logger  Logger
}

// NewSignedCommitsManager creates a new SignedCommitsManager
func NewSignedCommitsManager(logger Logger) *SignedCommitsManager {
	return &SignedCommitsManager{
		setting: SecuritySetting{
			Type:        SecurityTypeSignedCommits,
			Name:        "signed_commits",
			Description: "Requires all commits to be signed with GPG keys",
			Visibility:  VisibilityAny,
			Plan:        PlanAny,
			IsAvailable: func(info *RepoInfo) bool {
				// Required signatures are available for all repositories
				return true
			},
		},
		logger: logger,
	}
}

// GetSetting implements SecuritySettingManager GetSetting()
func (m *SignedCommitsManager) GetSetting() SecuritySetting {
	return m.setting
}

// GetValue implements SecuritySettingManager GetValue()
func (m *SignedCommitsManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	if !m.setting.IsAvailable(info) {
		return SecuritySettingValue{
			Enabled: false,
		}
	}

	protection, _, err := client.Repositories.GetSignaturesProtectedBranch(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if strings.Contains(err.Error(), "Branch not protected") {
			return SecuritySettingValue{
				Enabled: false,
			}
		}
		m.logger.Error("Failed to get signatures protection: %v", err)
		return SecuritySettingValue{
			Enabled: false,
			Error:   err,
		}
	}

	return SecuritySettingValue{
		Enabled: protection.Enabled != nil && *protection.Enabled,
		Value: map[string]interface{}{
			"branch": info.DefaultBranch,
		},
	}
}

// Enable implements SecuritySettingManager Enable()
func (m *SignedCommitsManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	if !m.setting.IsAvailable(info) {
		return fmt.Errorf("signed commits not available for this repository")
	}

	if config.DryRun {
		m.logger.Info("[DRY RUN] Would enable signed commits requirement")
		return nil
	}

	_, _, err := client.Repositories.RequireSignaturesOnProtectedBranch(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("failed to require signatures: %w", err)
	}

	return nil
}

// Disable implements SecuritySettingManager Disable()
func (m *SignedCommitsManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	if !m.setting.IsAvailable(info) {
		return fmt.Errorf("signed commits not available for this repository")
	}

	if config.DryRun {
		m.logger.Info("[DRY RUN] Would disable signed commits requirement")
		return nil
	}

	_, err := client.Repositories.OptionalSignaturesOnProtectedBranch(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("failed to make signatures optional: %w", err)
	}

	return nil
}
