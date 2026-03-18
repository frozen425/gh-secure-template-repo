package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// SecretScanningManager checks whether GitHub secret scanning is enabled.
type SecretScanningManager struct {
	setting SecuritySetting
}

func NewSecretScanningManager() *SecretScanningManager {
	return &SecretScanningManager{
		setting: SecuritySetting{
			Name:           "secret_scanning",
			Description:    "Secret scanning is enabled to detect leaked credentials",
			Type:           SecurityTypeSecurityFeature,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityCritical,
			RequiredScopes: []string{"repo"},
			IsAvailable: func(info *RepoInfo) (bool, string) {
				// Secret scanning is available on public repos for free,
				// and on private repos with GitHub Advanced Security (GHAS).
				if info.IsPrivate && !info.IsEnterprise {
					return false, "requires public repo or GitHub Advanced Security (repo is private)"
				}
				return true, ""
			},
		},
	}
}

func (m *SecretScanningManager) GetSetting() SecuritySetting { return m.setting }

func (m *SecretScanningManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	repo, _, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking secret scanning: %w", err)}
	}

	sa := repo.GetSecurityAndAnalysis()
	if sa == nil {
		return SecuritySettingValue{Enabled: false}
	}

	ss := sa.GetSecretScanning()
	if ss == nil {
		return SecuritySettingValue{Enabled: false}
	}

	enabled := ss.GetStatus() == "enabled"
	return SecuritySettingValue{Enabled: enabled}
}

func (m *SecretScanningManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning: &github.SecretScanning{
				Status: github.Ptr("enabled"),
			},
		},
	})
	return err
}

func (m *SecretScanningManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanning: &github.SecretScanning{
				Status: github.Ptr("disabled"),
			},
		},
	})
	return err
}

// SecretScanningPushProtectionManager checks whether push protection is
// enabled to block commits containing secrets.
type SecretScanningPushProtectionManager struct {
	setting SecuritySetting
}

func NewSecretScanningPushProtectionManager() *SecretScanningPushProtectionManager {
	return &SecretScanningPushProtectionManager{
		setting: SecuritySetting{
			Name:           "secret_scanning_push_protection",
			Description:    "Push protection blocks commits containing secrets",
			Type:           SecurityTypeSecurityFeature,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityCritical,
			RequiredScopes: []string{"repo"},
			IsAvailable: func(info *RepoInfo) (bool, string) {
				if info.IsPrivate && !info.IsEnterprise {
					return false, "requires public repo or GitHub Advanced Security (repo is private)"
				}
				return true, ""
			},
		},
	}
}

func (m *SecretScanningPushProtectionManager) GetSetting() SecuritySetting { return m.setting }

func (m *SecretScanningPushProtectionManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	repo, _, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking push protection: %w", err)}
	}

	sa := repo.GetSecurityAndAnalysis()
	if sa == nil {
		return SecuritySettingValue{Enabled: false}
	}

	pp := sa.GetSecretScanningPushProtection()
	if pp == nil {
		return SecuritySettingValue{Enabled: false}
	}

	enabled := pp.GetStatus() == "enabled"
	return SecuritySettingValue{Enabled: enabled}
}

func (m *SecretScanningPushProtectionManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanningPushProtection: &github.SecretScanningPushProtection{
				Status: github.Ptr("enabled"),
			},
		},
	})
	return err
}

func (m *SecretScanningPushProtectionManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, &github.Repository{
		SecurityAndAnalysis: &github.SecurityAndAnalysis{
			SecretScanningPushProtection: &github.SecretScanningPushProtection{
				Status: github.Ptr("disabled"),
			},
		},
	})
	return err
}
