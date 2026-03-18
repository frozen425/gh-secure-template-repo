package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"

	"gh-secure-template-repo/internal/auth"
	applog "gh-secure-template-repo/internal/log"
	"gh-secure-template-repo/settings"
)

// authFlags are parsed early and may short-circuit before repo flags are needed.
type authFlags struct {
	Login    bool
	Logout   bool
	Revoke   bool
	ClientID string
}

func parseFlags() (*settings.Config, *authFlags, error) {
	config := &settings.Config{}
	af := &authFlags{}

	flag.StringVar(&config.Name, "name", "", "Repository name")
	flag.StringVar(&config.Description, "description", "", "Repository description")
	flag.StringVar(&config.Owner, "owner", "", "Repository owner")
	flag.StringVar(&config.Author, "author", "", "Author name")
	flag.StringVar(&config.Org, "org", "", "Organization name")
	flag.BoolVar(&config.Private, "private", false, "Private repository")
	flag.BoolVar(&config.ForceUpdate, "force", false, "Force update / skip confirmation")
	flag.BoolVar(&config.TempDisable, "temp-disable", false, "Temporarily disable")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&config.License, "license", "", "License template")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Dry run mode")
	flag.BoolVar(&config.Assess, "assess", false, "Run security assessment (default when no mode flag is set)")
	flag.BoolVar(&config.Apply, "apply", false, "Apply remediation to failing checks")
	flag.StringVar(&config.Date, "date", time.Now().Format("2006-01-02"), "Date (YYYY-MM-DD)")

	// Configurable check parameters.
	flag.IntVar(&config.MinReviewers, "min-reviewers", 1, "Minimum required approving PR reviewers")
	flag.StringVar(&config.RawRequiredChecks, "required-checks", "", "Comma-separated status check contexts that must pass (e.g. 'ci/build,lint')")
	flag.BoolVar(&config.RequireCodeOwners, "require-codeowners", false, "Require code owner reviews on PRs")

	// Output format.
	flag.BoolVar(&config.JSONOutput, "json", false, "Output results as JSON")

	// Auth flags.
	flag.BoolVar(&af.Login, "login", false, "Authenticate via OAuth device flow")
	flag.BoolVar(&af.Logout, "logout", false, "Clear cached authentication token")
	flag.BoolVar(&af.Revoke, "revoke", false, "Revoke token: clear local cache and open GitHub settings to revoke server-side")
	flag.StringVar(&af.ClientID, "client-id", "", "GitHub OAuth App client ID (required for --login)")

	flag.Parse()

	// Parse comma-separated required checks.
	if config.RawRequiredChecks != "" {
		for _, c := range strings.Split(config.RawRequiredChecks, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				config.RequiredChecks = append(config.RequiredChecks, c)
			}
		}
	}

	// Default to assess mode when neither --assess nor --apply is specified.
	if !config.Assess && !config.Apply {
		config.Assess = true
	}

	// --login, --logout, and --revoke don't require --name/--owner.
	if !af.Login && !af.Logout && !af.Revoke {
		if config.Name == "" {
			return nil, nil, fmt.Errorf("repository name is required")
		}
		if config.Owner == "" {
			return nil, nil, fmt.Errorf("repository owner is required")
		}
	}

	return config, af, nil
}

func createGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func getRepoInfo(ctx context.Context, client *github.Client, config *settings.Config, caps *settings.TokenCapabilities) (*settings.RepoInfo, error) {
	repo, _, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	return &settings.RepoInfo{
		IsOrg:            repo.GetOwner().GetType() == "Organization",
		IsPrivate:        repo.GetPrivate(),
		IsPro:            caps.IsPro,
		IsEnterprise:     caps.IsEnterprise,
		PlanName:         caps.PlanName,
		OrgPlan:          caps.OrgPlan,
		HasIssues:        repo.GetHasIssues(),
		HasProjects:      repo.GetHasProjects(),
		HasWiki:          repo.GetHasWiki(),
		DefaultBranch:    repo.GetDefaultBranch(),
		AllowSquashMerge: repo.GetAllowSquashMerge(),
		AllowMergeCommit: repo.GetAllowMergeCommit(),
		AllowRebaseMerge: repo.GetAllowRebaseMerge(),
	}, nil
}

// registerAllSettings adds every security check to the registry.
// Order matters for --apply: branch_protection must be first because
// sub-settings (signed commits, reviews, status checks, etc.) require
// protection to exist before they can be enabled.
func registerAllSettings(registry *settings.SecuritySettingsRegistry) {
	// Foundation: branch protection must exist before sub-settings.
	registry.RegisterSetting("branch_protection", settings.NewBranchProtectionManager())

	// Branch protection sub-settings (depend on protection existing).
	registry.RegisterSetting("signed_commits", settings.NewSignedCommitsManager())
	registry.RegisterSetting("require_pr_reviews", settings.NewRequirePRReviewsManager())
	registry.RegisterSetting("dismiss_stale_reviews", settings.NewDismissStaleReviewsManager())
	registry.RegisterSetting("require_status_checks", settings.NewRequireStatusChecksManager())
	registry.RegisterSetting("enforce_admins", settings.NewEnforceAdminsManager())
	registry.RegisterSetting("force_push_protection", settings.NewForcePushProtectionManager())
	registry.RegisterSetting("branch_deletion_protection", settings.NewBranchDeletionProtectionManager())

	// Repository-level settings (independent of branch protection).
	registry.RegisterSetting("delete_branch_on_merge", settings.NewDeleteBranchOnMergeManager())
	registry.RegisterSetting("vulnerability_alerts", settings.NewVulnerabilityAlertsManager())

	// Security features.
	registry.RegisterSetting("secret_scanning", settings.NewSecretScanningManager())
	registry.RegisterSetting("secret_scanning_push_protection", settings.NewSecretScanningPushProtectionManager())
	registry.RegisterSetting("private_vulnerability_reporting", settings.NewPrivateVulnReportingManager())
}

// printTokenSummary logs the detected token capabilities.
func printTokenSummary(logger applog.Logger, caps *settings.TokenCapabilities, source auth.AuthSource) {
	logger.Info("Token authenticated as: %s", caps.Login)
	logger.Info("Auth source: %s", source)
	plan := caps.PlanName
	if plan == "" {
		plan = "unknown"
	}
	logger.Info("Plan: %s", plan)
	if caps.IsFineGrained {
		logger.Info("Token type: fine-grained PAT (scope pre-screening unavailable)")
	} else {
		logger.Info("Token type: classic PAT")
		logger.Info("Scopes: %s", strings.Join(caps.Scopes, ", "))
	}
	if caps.OrgPlan != "" {
		logger.Info("Org plan: %s", caps.OrgPlan)
	}
}

// printAssessmentReport prints a formatted table of assessment results
// followed by a summary section with totals and skip/error reasons.
func printAssessmentReport(logger applog.Logger, results []settings.AssessmentResult) {
	logger.Info("")
	logger.Info("%-8s  %-35s  %-8s  %s", "SEVERITY", "CHECK", "STATUS", "DETAIL")
	logger.Info("%-8s  %-35s  %-8s  %s", "--------", "-----", "------", "------")

	for _, r := range results {
		logger.Info("%-8s  %-35s  %-8s  %s",
			r.Severity,
			r.Name,
			r.Status,
			r.Detail,
		)
	}

	// Tally results.
	var pass, fail, skip, errCount int
	var skipped []settings.AssessmentResult
	var errored []settings.AssessmentResult

	for _, r := range results {
		switch r.Status {
		case settings.StatusPass:
			pass++
		case settings.StatusFail:
			fail++
		case settings.StatusSkipped:
			skip++
			skipped = append(skipped, r)
		case settings.StatusError:
			errCount++
			errored = append(errored, r)
		}
	}

	// Summary line.
	logger.Info("")
	logger.Info("Summary: %d passed, %d failed, %d skipped, %d errors  (total: %d)",
		pass, fail, skip, errCount, len(results))

	// Itemize skipped checks with reasons.
	if len(skipped) > 0 {
		logger.Warn("")
		logger.Warn("Skipped checks:")
		for _, r := range skipped {
			logger.Warn("  %-35s  %s", r.Name, r.Detail)
		}
	}

	// Itemize errored checks with reasons.
	if len(errored) > 0 {
		logger.Error("")
		logger.Error("Errors:")
		for _, r := range errored {
			logger.Error("  %-35s  %s", r.Name, r.Detail)
		}
	}

	logger.Info("")
}

// JSONReport is the top-level structure for --json output.
type JSONReport struct {
	Repository string                      `json:"repository"`
	Mode       string                      `json:"mode"`
	Results    []settings.AssessmentResult  `json:"results"`
	Summary    JSONSummary                  `json:"summary"`
}

type JSONSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

func printJSONReport(config *settings.Config, mode string, results []settings.AssessmentResult) {
	var s JSONSummary
	for _, r := range results {
		switch r.Status {
		case settings.StatusPass:
			s.Passed++
		case settings.StatusFail:
			s.Failed++
		case settings.StatusSkipped:
			s.Skipped++
		case settings.StatusError:
			s.Errors++
		}
	}
	s.Total = len(results)

	report := JSONReport{
		Repository: config.Owner + "/" + config.Name,
		Mode:       mode,
		Results:    results,
		Summary:    s,
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))
}

// outputReport dispatches to JSON or table report format.
func outputReport(logger applog.Logger, config *settings.Config, mode string, results []settings.AssessmentResult) {
	if config.JSONOutput {
		printJSONReport(config, mode, results)
	} else {
		printAssessmentReport(logger, results)
	}
}

// countFailures returns how many results have a FAIL status.
func countFailures(results []settings.AssessmentResult) int {
	n := 0
	for _, r := range results {
		if r.Status == settings.StatusFail {
			n++
		}
	}
	return n
}

func main() {
	config, af, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	logger := applog.NewLogger(config.Debug, config.JSONOutput)
	ctx := context.Background()

	// --- Handle --revoke ---
	if af.Revoke {
		if err := auth.Revoke(logger); err != nil {
			logger.Error("Revoke failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// --- Handle --logout ---
	if af.Logout {
		if err := auth.Logout(logger); err != nil {
			logger.Error("Logout failed: %v", err)
			os.Exit(1)
		}
		return
	}

	// --- Resolve authentication ---
	authResult, err := auth.ResolveToken(logger, af.ClientID, af.Login)
	if err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}

	// If --login only (no --name/--owner), just authenticate and exit.
	if af.Login && config.Name == "" {
		return
	}

	// --- GitHub client ---
	client := createGitHubClient(ctx, authResult.Token)

	// --- Pre-flight: detect token capabilities ---
	caps, err := settings.DetectTokenCapabilities(ctx, client, config.Org)
	if err != nil {
		logger.Error("Failed to detect token capabilities: %v", err)
		os.Exit(1)
	}

	printTokenSummary(logger, caps, authResult.Source)

	// --- Fetch repo info ---
	repoInfo, err := getRepoInfo(ctx, client, config, caps)
	if err != nil {
		logger.Error("Failed to get repository info: %v", err)
		os.Exit(1)
	}

	// --- Build registry ---
	registry := settings.NewSecuritySettingsRegistry(logger, caps)
	registerAllSettings(registry)

	// --- Run mode ---
	if config.DryRun {
		logger.Info("Running in dry-run mode — showing what --apply would do (no changes)")
		results := registry.AssessAll(ctx, client, *config, repoInfo)
		outputReport(logger, config, "dry-run", results)
		if f := countFailures(results); f > 0 {
			logger.Info("%d check(s) would be remediated by --apply", f)
		} else {
			logger.Info("All checks passing — nothing to remediate.")
		}
		return
	}

	if config.Apply {
		if !config.ForceUpdate {
			logger.Warn("--apply will modify repository settings. Use --force to skip this warning.")
			logger.Info("Proceeding in 5 seconds... (Ctrl+C to cancel)")
			time.Sleep(5 * time.Second)
		}
		logger.Info("Applying remediation to %s/%s ...", config.Owner, config.Name)
		results := registry.ApplyAll(ctx, client, *config, repoInfo)
		outputReport(logger, config, "apply", results)

		if f := countFailures(results); f > 0 {
			logger.Error("%d check(s) still failing after remediation", f)
			os.Exit(1)
		}
		logger.Info("All checks passing.")
		return
	}

	// Default: assess
	logger.Info("Assessing security posture for %s/%s ...", config.Owner, config.Name)
	results := registry.AssessAll(ctx, client, *config, repoInfo)
	outputReport(logger, config, "assess", results)

	if f := countFailures(results); f > 0 {
		logger.Error("%d check(s) failing", f)
		os.Exit(1)
	}
	logger.Info("All checks passing.")
}
