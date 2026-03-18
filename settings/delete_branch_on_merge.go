package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// DeleteBranchOnMergeManager checks whether head branches are automatically
// deleted after pull requests are merged.
type DeleteBranchOnMergeManager struct {
	setting SecuritySetting
}

func NewDeleteBranchOnMergeManager() *DeleteBranchOnMergeManager {
	return &DeleteBranchOnMergeManager{
		setting: SecuritySetting{
			Name:           "delete_branch_on_merge",
			Description:    "Head branches are automatically deleted after PR merge",
			Type:           SecurityTypeRepoSetting,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityLow,
			RequiredScopes: []string{"repo"},
			IsAvailable: func(info *RepoInfo) (bool, string) {
				return true, ""
			},
		},
	}
}

func (m *DeleteBranchOnMergeManager) GetSetting() SecuritySetting { return m.setting }

func (m *DeleteBranchOnMergeManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	repo, _, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking delete branch on merge: %w", err)}
	}
	return SecuritySettingValue{
		Enabled: repo.GetDeleteBranchOnMerge(),
	}
}

func (m *DeleteBranchOnMergeManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		DeleteBranchOnMerge: github.Ptr(true),
	})
	return err
}

func (m *DeleteBranchOnMergeManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		DeleteBranchOnMerge: github.Ptr(false),
	})
	return err
}
