package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// EnforceAdminsManager checks whether branch protection rules are enforced
// for repository administrators as well.
type EnforceAdminsManager struct {
	setting SecuritySetting
}

func NewEnforceAdminsManager() *EnforceAdminsManager {
	return &EnforceAdminsManager{
		setting: SecuritySetting{
			Name:           "enforce_admins",
			Description:    "Branch protection rules apply to repository administrators",
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

func (m *EnforceAdminsManager) GetSetting() SecuritySetting { return m.setting }

func (m *EnforceAdminsManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking enforce admins: %w", err)}
	}

	admin := protection.GetEnforceAdmins()
	if admin == nil {
		return SecuritySettingValue{Enabled: false}
	}

	return SecuritySettingValue{
		Enabled: admin.Enabled,
	}
}

func (m *EnforceAdminsManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.AddAdminEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}

func (m *EnforceAdminsManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, err := client.Repositories.RemoveAdminEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}
