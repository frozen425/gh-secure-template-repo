package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// DismissStaleReviewsManager checks whether stale pull request reviews are
// automatically dismissed when new commits are pushed.
type DismissStaleReviewsManager struct {
	setting SecuritySetting
}

func NewDismissStaleReviewsManager() *DismissStaleReviewsManager {
	return &DismissStaleReviewsManager{
		setting: SecuritySetting{
			Name:           "dismiss_stale_reviews",
			Description:    "Stale pull request reviews are dismissed on new commits",
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

func (m *DismissStaleReviewsManager) GetSetting() SecuritySetting { return m.setting }

func (m *DismissStaleReviewsManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, config.Owner, config.Name, info.DefaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking dismiss stale reviews: %w", err)}
	}

	reviews := protection.GetRequiredPullRequestReviews()
	if reviews == nil {
		return SecuritySettingValue{Enabled: false}
	}

	return SecuritySettingValue{
		Enabled: reviews.DismissStaleReviews,
	}
}

func (m *DismissStaleReviewsManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	req := &github.PullRequestReviewsEnforcementUpdate{
		DismissStaleReviews: github.Ptr(true),
	}
	_, _, err := client.Repositories.UpdatePullRequestReviewEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}

func (m *DismissStaleReviewsManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	req := &github.PullRequestReviewsEnforcementUpdate{
		DismissStaleReviews: github.Ptr(false),
	}
	_, _, err := client.Repositories.UpdatePullRequestReviewEnforcement(ctx, config.Owner, config.Name, info.DefaultBranch, req)
	return err
}
