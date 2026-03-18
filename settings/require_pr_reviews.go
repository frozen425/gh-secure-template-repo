package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// RequirePRReviewsManager checks whether PRs require at least one approving
// review before merging to the default branch.
type RequirePRReviewsManager struct {
	setting SecuritySetting
}

func NewRequirePRReviewsManager() *RequirePRReviewsManager {
	return &RequirePRReviewsManager{
		setting: SecuritySetting{
			Name:           "require_pr_reviews",
			Description:    "Pull requests require at least 1 approving review",
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

func (m *RequirePRReviewsManager) GetSetting() SecuritySetting { return m.setting }

func (m *RequirePRReviewsManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking PR review requirements: %w", err)}
	}

	reviews := protection.GetRequiredPullRequestReviews()
	if reviews == nil {
		return SecuritySettingValue{Enabled: false}
	}

	count := reviews.RequiredApprovingReviewCount
	minRequired := config.MinReviewers
	if minRequired < 1 {
		minRequired = 1
	}

	enabled := count >= minRequired
	return SecuritySettingValue{
		Enabled: enabled,
		Value: map[string]interface{}{
			"required_approving_review_count": count,
			"minimum_required":               minRequired,
			"require_code_owner_reviews":      reviews.RequireCodeOwnerReviews,
		},
	}
}

func (m *RequirePRReviewsManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	minRequired := config.MinReviewers
	if minRequired < 1 {
		minRequired = 1
	}
	req := &github.PullRequestReviewsEnforcementUpdate{
		RequiredApprovingReviewCount: minRequired,
		RequireCodeOwnerReviews:     github.Ptr(config.RequireCodeOwners),
	}
	_, _, err := client.Repositories.UpdatePullRequestReviewEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}

func (m *RequirePRReviewsManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, err := client.Repositories.RemovePullRequestReviewEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch)
	return err
}
