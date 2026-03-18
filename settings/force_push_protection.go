package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// ForcePushProtectionManager checks whether force pushes are blocked on the
// default branch.
type ForcePushProtectionManager struct {
	setting SecuritySetting
}

func NewForcePushProtectionManager() *ForcePushProtectionManager {
	return &ForcePushProtectionManager{
		setting: SecuritySetting{
			Name:           "force_push_protection",
			Description:    "Force pushes are blocked on the default branch",
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

func (m *ForcePushProtectionManager) GetSetting() SecuritySetting { return m.setting }

func (m *ForcePushProtectionManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			// No branch protection means force pushes are allowed.
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking force push protection: %w", err)}
	}

	afp := protection.GetAllowForcePushes()
	if afp == nil {
		// If AllowForcePushes is nil, force pushes are blocked (default when protection exists).
		return SecuritySettingValue{Enabled: true}
	}

	// AllowForcePushes.Enabled == true means force pushes ARE allowed → protection is OFF.
	return SecuritySettingValue{
		Enabled: !afp.Enabled,
	}
}

func (m *ForcePushProtectionManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	// To block force pushes we need to update branch protection with AllowForcePushes=false.
	// We get existing protection first to preserve other settings.
	protection, _, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("cannot read existing protection to update force push setting: %w", err)
	}

	req := protectionToRequest(protection)
	req.AllowForcePushes = github.Ptr(false)

	_, _, err = client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}

func (m *ForcePushProtectionManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	protection, _, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		return fmt.Errorf("cannot read existing protection to update force push setting: %w", err)
	}

	req := protectionToRequest(protection)
	req.AllowForcePushes = github.Ptr(true)

	_, _, err = client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}
