package settings

import (
	"context"

	"github.com/google/go-github/v68/github"
)

// SecuritySettingType represents the type of security setting
type SecuritySettingType int

const (
	SecurityTypeBranchProtection SecuritySettingType = iota
	SecurityTypeRuleset
	SecurityTypeRepository
	SecurityTypeSignedCommits
)

// String returns the string representation of SecuritySettingType
func (t SecuritySettingType) String() string {
	switch t {
	case SecurityTypeBranchProtection:
		return "Branch Protection"
	case SecurityTypeRuleset:
		return "Ruleset"
	case SecurityTypeRepository:
		return "Repository"
	case SecurityTypeSignedCommits:
		return "Signed Commits"
	default:
		return "Unknown"
	}
}

// SecuritySettingVisibility represents the visibility requirements
type SecuritySettingVisibility int

const (
	VisibilityAny SecuritySettingVisibility = iota
	VisibilityPublicOnly
	VisibilityPrivateOnly
)

// String returns the string representation of SecuritySettingVisibility
func (v SecuritySettingVisibility) String() string {
	switch v {
	case VisibilityAny:
		return "Any"
	case VisibilityPublicOnly:
		return "Public Only"
	case VisibilityPrivateOnly:
		return "Private Only"
	default:
		return "Unknown"
	}
}

// SecuritySettingPlan represents the billing plan requirements
type SecuritySettingPlan int

const (
	PlanAny SecuritySettingPlan = iota
	PlanFree
	PlanTeam
	PlanPro
	PlanEnterprise
)

// String returns the string representation of SecuritySettingPlan
func (p SecuritySettingPlan) String() string {
	switch p {
	case PlanAny:
		return "Any"
	case PlanFree:
		return "Free"
	case PlanTeam:
		return "Team"
	case PlanPro:
		return "Pro"
	case PlanEnterprise:
		return "Enterprise"
	default:
		return "Unknown"
	}
}

// SecuritySetting represents a GitHub repository security setting
type SecuritySetting struct {
	Name        string
	Description string
	Type        SecuritySettingType
	Visibility  SecuritySettingVisibility
	Plan        SecuritySettingPlan
	IsAvailable func(info *RepoInfo) bool
}

// SecuritySettingValue represents the current value/state of a security setting
type SecuritySettingValue struct {
	Enabled bool
	Value   interface{} // Additional setting-specific data
	Error   error       // Any error encountered while fetching the value
}

// SecuritySettingManager interface defines methods for managing a security setting
type SecuritySettingManager interface {
	// GetSetting returns the SecuritySetting metadata
	GetSetting() SecuritySetting
	// GetValue gets the current value/state of the security setting
	GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue
	// Enable enables the security setting
	Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error
	// Disable disables the security setting
	Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error
}

// RepoInfo holds repository metadata and capabilities
type RepoInfo struct {
	IsOrg            bool
	IsPrivate        bool
	IsPro            bool
	IsEnterprise     bool
	PlanName         string
	OrgPlan          string
	HasIssues        bool
	HasProjects      bool
	HasWiki          bool
	DefaultBranch    string
	AllowSquashMerge bool
	AllowMergeCommit bool
	AllowRebaseMerge bool
}

// Config holds the configuration for the security settings
type Config struct {
	Name          string
	Description   string
	Author        string
	Owner         string
	Org           string
	DefaultBranch string
	Private       bool
	License       string
	ForceUpdate   bool
	DryRun        bool
	Debug         bool
	Date          string
}
