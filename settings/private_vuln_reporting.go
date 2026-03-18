package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"
)

// PrivateVulnReportingManager checks whether private vulnerability reporting
// is enabled, allowing security researchers to report issues directly.
type PrivateVulnReportingManager struct {
	setting SecuritySetting
}

func NewPrivateVulnReportingManager() *PrivateVulnReportingManager {
	return &PrivateVulnReportingManager{
		setting: SecuritySetting{
			Name:           "private_vulnerability_reporting",
			Description:    "Private vulnerability reporting is enabled for researchers",
			Type:           SecurityTypeSecurityFeature,
			Visibility:     VisibilityAny,
			Plan:           PlanAny,
			Severity:       SeverityMedium,
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

func (m *PrivateVulnReportingManager) GetSetting() SecuritySetting { return m.setting }

func (m *PrivateVulnReportingManager) GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue {
	enabled, resp, err := client.Repositories.IsPrivateReportingEnabled(ctx, config.Owner, config.Name)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			return SecuritySettingValue{Enabled: false}
		}
		return SecuritySettingValue{Enabled: false, Error: fmt.Errorf("error checking private vulnerability reporting: %w", err)}
	}
	return SecuritySettingValue{Enabled: enabled}
}

func (m *PrivateVulnReportingManager) Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	resp, err := client.Repositories.EnablePrivateReporting(ctx, config.Owner, config.Name)
	if err != nil && resp != nil && resp.StatusCode == 404 {
		return fmt.Errorf("private vulnerability reporting not available for this repository")
	}
	return err
}

func (m *PrivateVulnReportingManager) Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error {
	_, err := client.Repositories.DisablePrivateReporting(ctx, config.Owner, config.Name)
	return err
}
