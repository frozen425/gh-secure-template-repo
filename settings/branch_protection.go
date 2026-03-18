package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// BranchProtectionManager checks whether the default branch has any branch
// protection rules enabled at all.
type BranchProtectionManager struct {
	setting SecuritySetting
}

func NewBranchProtectionManager() *BranchProtectionManager {
	return &BranchProtectionManager{
		setting: SecuritySetting{
			Name:           "branch_protection",
			Description:    "Default branch has protection rules enabled",
			Type:           SecurityTypeBranchProtection,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityCritical,
			RequiredScopes: []string{"repo"},
			IsAvailable: func(info *RepoInfo) (bool, string) {
				return true, ""
			},
		},
	}
}

func (m *BranchProtectionManager) GetSetting() SecuritySetting { return m.setting }

func (m *BranchProtectionManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	_, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking branch protection: %w", err)}
	}
	return SecuritySettingValue{
		Enabled: true,
		Value:   map[string]interface{}{"branch": info.DefaultBranch},
	}
}

func (m *BranchProtectionManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	// Enable branch protection with defaults from config.
	minReviewers := config.MinReviewers
	if minReviewers < 1 {
		minReviewers = 1
	}
	req := &github.ProtectionRequest{
		RequiredPullRequestReviews: &github.PullRequestReviewsEnforcementRequest{
			RequiredApprovingReviewCount: minReviewers,
			RequireCodeOwnerReviews:     config.RequireCodeOwners,
		},
		EnforceAdmins: true,
		AllowForcePushes: github.Ptr(false),
		AllowDeletions:   github.Ptr(false),
	}
	_, _, err := client.Repositories.UpdateBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}

func (m *BranchProtectionManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, err := client.Repositories.RemoveBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}
