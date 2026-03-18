package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// BranchDeletionProtectionManager checks whether the default branch is
// protected from deletion.
type BranchDeletionProtectionManager struct {
	setting SecuritySetting
}

func NewBranchDeletionProtectionManager() *BranchDeletionProtectionManager {
	return &BranchDeletionProtectionManager{
		setting: SecuritySetting{
			Name:           "branch_deletion_protection",
			Description:    "Default branch is protected from deletion",
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

func (m *BranchDeletionProtectionManager) GetSetting() SecuritySetting { return m.setting }

func (m *BranchDeletionProtectionManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking branch deletion protection: %w", err)}
	}

	ad := protection.GetAllowDeletions()
	if ad == nil {
		// If AllowDeletions is nil, deletions are blocked (default when protection exists).
		return SecuritySettingValue{Enabled: true}
	}

	// AllowDeletions.Enabled == true means deletions ARE allowed → protection is OFF.
	return SecuritySettingValue{
		Enabled: !ad.Enabled,
	}
}

func (m *BranchDeletionProtectionManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	protection, _, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("cannot read existing protection to update deletion setting: %w", err)
	}

	req := protectionToRequest(protection)
	req.AllowDeletions = github.Ptr(false)

	_, _, err = client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}

func (m *BranchDeletionProtectionManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	protection, _, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("cannot read existing protection to update deletion setting: %w", err)
	}

	req := protectionToRequest(protection)
	req.AllowDeletions = github.Ptr(true)

	_, _, err = client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}
