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
	"gh-secure-template-repo/templatefiles"
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
	flag.StringVar(&config.DefaultBranch, "default-branch", "main", "Default branch name for new repositories")

	flag.Parse()

	if config.Name == "" {
		return nil, fmt.Errorf("repository name is required")
	}

	// Set default owner: use org if provided, otherwise use author
	if config.Owner == "" {
		if config.Org != "" {
			config.Owner = config.Org
		} else if config.Author != "" {
			config.Owner = config.Author
		} else {
			return nil, fmt.Errorf("one of -owner, -org, or -author is required")
		}
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
				Name:          github.Ptr(config.Name),
				Description:   github.Ptr(config.Description),
				Private:       github.Ptr(config.Private),
				HasIssues:     github.Ptr(true),
				HasWiki:       github.Ptr(true),
				AutoInit:      github.Ptr(false),
				DefaultBranch: github.Ptr(config.DefaultBranch),
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

func updateRepoSettings(ctx context.Context, client *github.Client, config *settings.Config, repo *github.Repository, logger *Logger) error {
	// Create update request with only settings that apply to both personal and org repos
	update := &github.Repository{
		Name:        github.Ptr(config.Name),
		Description: github.Ptr(config.Description),
		Private:     github.Ptr(config.Private),
		HasIssues:   repo.HasIssues,
		HasWiki:     repo.HasWiki,
	}

	// Only set org-specific settings if this is an org repo
	if config.Org != "" {
		logger.Debug("Updating organization repository settings")
		update.AllowForking = repo.AllowForking
		update.AllowMergeCommit = repo.AllowMergeCommit
		update.AllowSquashMerge = repo.AllowSquashMerge
		update.AllowRebaseMerge = repo.AllowRebaseMerge
	} else {
		logger.Debug("Updating personal repository settings")
	}

	_, _, err := client.Repositories.Edit(ctx, config.Owner, config.Name, update)
	if err != nil {
		return fmt.Errorf("failed to update repository settings: %w", err)
	}
	logger.Info("Repository settings updated successfully")
	return nil
}

func renderAndCreateTemplates(ctx context.Context, client *github.Client, config *settings.Config, logger *Logger) error {
	// Prepare template parameters
	params := templatefiles.TemplateParams{
		Name:        config.Name,
		Description: config.Description,
		Author:      config.Author,
		Owner:       config.Owner,
		RepoType:    "personal",
		Visibility:  "private",
		Plan:        "free",
		License:     config.License,
		Year:        time.Now().Format("2006"),
	}
	logger.Debug("Template params initialized: %+v", params)

	// Set organization-specific values if applicable
	if config.Org != "" {
		params.Owner = config.Org
		params.RepoType = "organization"
		logger.Debug("Final template params (with org): %+v", params)
	}

	// Render all templates
	renderedFiles, err := templatefiles.RenderTemplateFiles(params)
	if err != nil {
		return fmt.Errorf("failed to render templates: %w", err)
	}

	// Get repository info to get default branch
	if !config.DryRun {
		repoInfo, err := getRepoInfo(ctx, client, config)
		if err != nil {
			return fmt.Errorf("failed to get repository info: %w", err)
		}
		config.DefaultBranch = repoInfo.DefaultBranch
	}

	// Create or update each file in the repository
	for path, content := range renderedFiles {
		// Create commit message
		message := fmt.Sprintf("Initialize %s", path)

		// Check if file exists
		_, _, resp, err := client.Repositories.GetContents(ctx, config.Owner, config.Name, path, &github.RepositoryContentGetOptions{
			Ref: config.DefaultBranch,
		})

		fileExists := err == nil || (resp != nil && resp.StatusCode != 404)

		if fileExists && !config.ForceUpdate {
			logger.Debug("Skipping existing file %s (use --force to update)", path)
			continue
		}

		if config.DryRun {
			if fileExists {
				logger.Info("[DRY RUN] Would update file: %s", path)
			} else {
				logger.Info("[DRY RUN] Would create file: %s", path)
			}
			continue
		}

		// Create the file content
		fileContent := &github.RepositoryContentFileOptions{
			Message: &message,
			Content: []byte(content),
			Branch:  &config.DefaultBranch,
		}

		logger.Debug("Creating/updating file: %s", path)
		_, _, err = client.Repositories.CreateFile(ctx, config.Owner, config.Name, path, fileContent)
		if err != nil {
			return fmt.Errorf("failed to create/update file %s: %w", path, err)
		}
	}

	return nil
}

func main() {
	ctx := context.Background()

	// Parse command line flags
	config, err := parseFlags()
	if err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Create logger
	logger := NewLogger(config.Debug)

	// Create GitHub client
	client, err := createGitHubClient(ctx)
	if err != nil {
		logger.Error("Failed to create GitHub client: %v", err)
		os.Exit(1)
	}

	// Validate GitHub credentials
	if err := validateGitHubCredentials(ctx, client, logger); err != nil {
		logger.Error("Failed to validate GitHub credentials: %v", err)
		os.Exit(1)
	}

	// Check if repository exists
	repo, resp, err := client.Repositories.Get(ctx, config.Owner, config.Name)
	repoExists := err == nil
	if err != nil && (resp == nil || resp.StatusCode != 404) {
		logger.Error("Failed to check repository existence: %v", err)
		os.Exit(1)
	}

	if repoExists && !config.ForceUpdate {
		logger.Error("Repository %s/%s already exists. Use --force to update existing repository", config.Owner, config.Name)
		os.Exit(1)
	}

	// Create security settings registry
	registry := settings.NewSecuritySettingsRegistry(logger)

	// Register security settings
	registry.RegisterSetting("branch_protection", settings.NewBranchProtectionManager())
	registry.RegisterSetting("signed_commits", settings.NewSignedCommitsManager())

	logger.Debug("Configuration:")
	logger.Debug("  Repository: %s/%s", config.Owner, config.Name)
	logger.Debug("  Default Branch: %s", config.DefaultBranch)
	logger.Debug("  Private: %v", config.Private)
	logger.Debug("  Force Update: %v", config.ForceUpdate)
	logger.Debug("  Debug: %v", config.Debug)
	logger.Debug("  Dry Run: %v", config.DryRun)

	// For existing repos with force update
	if repoExists && config.ForceUpdate {
		if config.TempDisable {
			logger.Info("Temporarily disabling security settings for update")
			// Get current repo info
			repoInfo, err := getRepoInfo(ctx, client, config)
			if err != nil {
				logger.Error("Failed to get repository info: %v", err)
				os.Exit(1)
			}

			// Disable all settings first
			config.TempDisable = true
			registry.ApplySettings(ctx, client, *config, repoInfo)
			config.TempDisable = false // Reset for later re-enabling
		}

		// Update repository settings if needed
		if err := updateRepoSettings(ctx, client, config, repo, logger); err != nil {
			logger.Error("Failed to update repository settings: %v", err)
			os.Exit(1)
		}
	} else if !repoExists {
		// Create new repository
		if err := createOrUpdateRepo(ctx, client, config, logger); err != nil {
			logger.Error("Failed to create repository: %v", err)
			os.Exit(1)
		}
	}

	// Get repository info for settings
	repoInfo, err := getRepoInfo(ctx, client, config)
	if err != nil {
		logger.Error("Failed to get repository info: %v", err)
		os.Exit(1)
	}

	// Create/update template files
	if err := renderAndCreateTemplates(ctx, client, config, logger); err != nil {
		logger.Error("Failed to create template files: %v", err)
		os.Exit(1)
	}

	// Apply security settings
	registry.ApplySettings(ctx, client, *config, repoInfo)

	logger.Info("Repository setup completed successfully")
}
