package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"

	"gh-secure-template-repo/settings"
)

// Logger provides structured logging with debug support
type Logger struct {
	debug bool
}

func NewLogger(debug bool) *Logger {
	return &Logger{debug: debug}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func parseFlags() (*settings.Config, error) {
	config := &settings.Config{}

	flag.StringVar(&config.Name, "name", "", "Repository name")
	flag.StringVar(&config.Description, "description", "", "Repository description")
	flag.StringVar(&config.Owner, "owner", "", "Repository owner")
	flag.StringVar(&config.Author, "author", "", "Author name")
	flag.StringVar(&config.Org, "org", "", "Organization name")
	flag.BoolVar(&config.Private, "private", false, "Private repository")
	flag.BoolVar(&config.ForceUpdate, "force", false, "Force update")
	flag.BoolVar(&config.TempDisable, "temp-disable", false, "Temporarily disable")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&config.License, "license", "", "License template")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Dry run mode")
	flag.StringVar(&config.Date, "date", time.Now().Format("2006-01-02"), "Date (YYYY-MM-DD)")

	flag.Parse()

	if config.Name == "" {
		return nil, fmt.Errorf("repository name is required")
	}

	if config.Owner == "" {
		return nil, fmt.Errorf("repository owner is required")
	}

	return config, nil
}

func createGitHubClient(ctx context.Context) (*github.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc), nil
}

func validateGitHubCredentials(ctx context.Context, client *github.Client, logger *Logger) error {
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to validate GitHub credentials: %w", err)
	}

	logger.Debug("Authenticated as GitHub user:")
	logger.Debug("  Login: %s", user.GetLogin())
	logger.Debug("  Name: %s", user.GetName())
	logger.Debug("  Email: %s", user.GetEmail())
	logger.Debug("  Plan: %s", user.GetPlan().GetName())

	return nil
}

func getRepoInfo(ctx context.Context, client *github.Client, config *settings.Config) (*settings.RepoInfo, error) {
	repo, _, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	return &settings.RepoInfo{
		IsOrg:            repo.GetOwner().GetType() == "Organization",
		IsPrivate:        repo.GetPrivate(),
		IsPro:            true, // We'll assume Pro if we can access the repo
		IsEnterprise:     repo.GetVisibility() == "internal",
		PlanName:         "", // Not available from repo API
		OrgPlan:          "", // Not available from repo API
		HasIssues:        repo.GetHasIssues(),
		HasProjects:      repo.GetHasProjects(),
		HasWiki:          repo.GetHasWiki(),
		DefaultBranch:    repo.GetDefaultBranch(),
		AllowSquashMerge: repo.GetAllowSquashMerge(),
		AllowMergeCommit: repo.GetAllowMergeCommit(),
		AllowRebaseMerge: repo.GetAllowRebaseMerge(),
	}, nil
}

func createOrUpdateRepo(ctx context.Context, client *github.Client, config *settings.Config, logger *Logger) error {
	repo, resp, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			logger.Info("Creating new repository %s/%s", config.Owner, config.Name)
			repo := &github.Repository{
				Name:        github.Ptr(config.Name),
				Description: github.Ptr(config.Description),
				Private:     github.Ptr(config.Private),
				HasIssues:   github.Ptr(true),
				HasWiki:     github.Ptr(true),
				AutoInit:    github.Ptr(true),
			}
			_, _, err := client.Repositories.Create(ctx, config.Org, repo)
			if err != nil {
				return fmt.Errorf("failed to create repository: %w", err)
			}
			logger.Info("Repository created successfully")
			return nil
		}
		return fmt.Errorf("failed to check repository existence: %w", err)
	}

	if config.ForceUpdate {
		logger.Info("Updating repository %s/%s", config.Owner, config.Name)
		repo.Description = github.Ptr(config.Description)
		repo.Private = github.Ptr(config.Private)
		_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, repo)
		if err != nil {
			return fmt.Errorf("failed to update repository: %w", err)
		}
		logger.Info("Repository updated successfully")
	}

	return nil
}

func main() {
	config, err := parseFlags()
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	logger := NewLogger(config.Debug)

	ctx := context.Background()

	client, err := createGitHubClient(ctx)
	if err != nil {
		logger.Error("Error creating GitHub client: %v", err)
		os.Exit(1)
	}

	if err := validateGitHubCredentials(ctx, client, logger); err != nil {
		logger.Error("Error validating GitHub credentials: %v", err)
		os.Exit(1)
	}

	// Initialize security settings registry
	registry := settings.NewSecuritySettingsRegistry(logger)

	// Register security settings
	registry.RegisterSetting("signed_commits", settings.NewSignedCommitsManager())

	if config.DryRun {
		logger.Info("Running in dry-run mode - no changes will be made")
		// Use demo values for dry run
		registry.DebugPrintSettings(ctx, client, *config, &settings.RepoInfo{
			DefaultBranch: "main", // Default for demonstration
			IsPro:         true,   // Assuming Pro for demonstration
		})
	} else {
		// Create or update repository if needed
		if err := createOrUpdateRepo(ctx, client, config, logger); err != nil {
			logger.Error("Repository setup failed: %v", err)
			os.Exit(1)
		}

		// Get actual repository information
		repoInfo, err := getRepoInfo(ctx, client, config)
		if err != nil {
			logger.Error("Failed to get repository info: %v", err)
			os.Exit(1)
		}
		registry.DebugPrintSettings(ctx, client, *config, repoInfo)
	}

	logger.Debug("Configuration:")
	logger.Debug("  Repository: %s/%s", config.Owner, config.Name)
	logger.Debug("  Private: %v", config.Private)
	logger.Debug("  Force Update: %v", config.ForceUpdate)
	logger.Debug("  Debug: %v", config.Debug)
	logger.Debug("  Dry Run: %v", config.DryRun)
}
