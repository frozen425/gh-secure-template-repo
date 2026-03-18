package settings

import (
	"context"
	"fmt"

	"github.com/google/go-github/v68/github"

	applog "gh-secure-template-repo/internal/log"
)

// Severity indicates how critical a security setting is.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.String())), nil
}

// SecuritySettingType represents the type of security setting.
type SecuritySettingType int

const (
	SecurityTypeBranchProtection SecuritySettingType = iota
	SecurityTypeRuleset
	SecurityTypeRepoSetting
	SecurityTypeSecurityFeature
)

func (t SecuritySettingType) String() string {
	switch t {
	case SecurityTypeBranchProtection:
		return "Branch Protection"
	case SecurityTypeRuleset:
		return "Ruleset"
	case SecurityTypeRepoSetting:
		return "Repository Setting"
	case SecurityTypeSecurityFeature:
		return "Security Feature"
	default:
		return "Unknown"
	}
}

// SecuritySettingVisibility represents the visibility requirements.
type SecuritySettingVisibility int

const (
	VisibilityAny SecuritySettingVisibility = iota
	VisibilityPublicOnly
	VisibilityPrivateOnly
)

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

// SecuritySettingPlan represents the billing plan requirements.
type SecuritySettingPlan int

const (
	PlanAny SecuritySettingPlan = iota
	PlanFree
	PlanTeam
	PlanPro
	PlanEnterprise
)

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

// SecuritySetting represents a GitHub repository security setting.
type SecuritySetting struct {
	Name           string
	Description    string
	Type           SecuritySettingType
	Visibility     SecuritySettingVisibility
	Plan           SecuritySettingPlan
	Severity       Severity
	RequiredScopes []string // OAuth scopes the token needs for this check
	// IsAvailable returns whether this check can run against the given repo.
	// If false, the second return value explains why (e.g. plan or visibility).
	IsAvailable func(info *RepoInfo) (bool, string)
}

// SecuritySettingValue represents the current value/state of a security setting.
type SecuritySettingValue struct {
	Enabled bool
	Value   interface{} // Additional setting-specific data
	Error   error       // Any error encountered while fetching the value
}

// AssessmentStatus is the outcome of a single security check.
type AssessmentStatus int

const (
	StatusPass AssessmentStatus = iota
	StatusFail
	StatusError
	StatusSkipped
)

func (s AssessmentStatus) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusFail:
		return "FAIL"
	case StatusError:
		return "ERROR"
	case StatusSkipped:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

func (s AssessmentStatus) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.String())), nil
}

// AssessmentResult captures the outcome of evaluating one security setting.
type AssessmentResult struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Severity    Severity         `json:"severity"`
	Status      AssessmentStatus `json:"status"`
	Detail      string           `json:"detail"`
}

// SecuritySettingManager defines methods for managing a security setting.
type SecuritySettingManager interface {
	GetSetting() SecuritySetting
	GetValue(ctx context.Context, client *github.Client, config Config, info *RepoInfo) SecuritySettingValue
	Enable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error
	Disable(ctx context.Context, client *github.Client, config Config, info *RepoInfo) error
}

// RepoInfo holds repository metadata and capabilities.
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

// Config holds all configuration options for the tool.
type Config struct {
	Name        string
	Description string
	Owner       string
	Author      string
	Org         string
	Private     bool
	ForceUpdate bool
	TempDisable bool
	Debug       bool
	License     string
	DryRun      bool
	Date        string
	Assess     bool // run assessment (default mode)
	Apply      bool // apply remediation to failing checks
	JSONOutput bool // output results as JSON

	// Configurable check parameters (with sensible defaults).
	MinReviewers      int      // minimum required approving PR reviewers (default: 1)
	RequiredChecks    []string // status check contexts that must pass (default: none)
	RequireCodeOwners bool     // require code owner reviews (default: false)

	// Internal: raw CLI string for RequiredChecks before splitting.
	RawRequiredChecks string
}

// Ensure Logger interface is used (re-exported for convenience).
var _ applog.Logger = (*applog.StdLogger)(nil)
