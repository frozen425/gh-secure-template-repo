package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
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
	flag.StringVar(&config.License, "license", "", "License template")
	flag.StringVar(&config.DefaultBranch, "branch", "main", "Default branch name")
	flag.BoolVar(&config.Private, "private", false, "Create a private repository")
	flag.BoolVar(&config.ForceUpdate, "force", false, "Force update existing repository (will temporarily disable security settings)")
	flag.BoolVar(&config.DryRun, "dry-run", false, "Show what would be done without making changes")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&config.Date, "date", time.Now().Format("2006-01-02"), "Date (YYYY-MM-DD)")

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
		Year:        strconv.Itoa(time.Now().Year()),
		IsOrg:       config.Org != "",
	}

	if config.Org != "" {
		params.RepoType = "organization"
	}
	if !config.Private {
		params.Visibility = "public"
	}

	logger.Debug("Template params initialized: %+v", params)

	// Render all template files
	renderedFiles, err := templatefiles.RenderTemplateFiles(params)
	if err != nil {
		return fmt.Errorf("failed to render templates: %w", err)
	}

	// Create or update each template file
	for filename, content := range renderedFiles {
		logger.Debug("Creating/updating file: %s", filename)

		// Check if file exists
		fileContent, _, _, err := client.Repositories.GetContents(ctx, config.Owner, config.Name, filename, &github.RepositoryContentGetOptions{})
		
		var opts *github.RepositoryContentFileOptions
		if err == nil && fileContent != nil {
			// File exists, update it
			opts = &github.RepositoryContentFileOptions{
				Message: github.Ptr(fmt.Sprintf("Update %s", filename)),
				Content: []byte(content),
				SHA:     fileContent.SHA,
				Branch:  github.Ptr(config.DefaultBranch),
			}
		} else {
			// File doesn't exist, create it
			opts = &github.RepositoryContentFileOptions{
				Message: github.Ptr(fmt.Sprintf("Create %s", filename)),
				Content: []byte(content),
				Branch:  github.Ptr(config.DefaultBranch),
			}
		}

		_, _, err = client.Repositories.CreateFile(ctx, config.Owner, config.Name, filename, opts)
		if err != nil {
			return fmt.Errorf("failed to create/update file %s: %w", filename, err)
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
	_, resp, err := client.Repositories.Get(ctx, config.Owner, config.Name)
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
	registry.RegisterSetting("repository_settings", settings.NewRepoSettingsManager(logger))
	registry.RegisterSetting("branch_protection", settings.NewBranchProtectionManager(logger))
	registry.RegisterSetting("signed_commits", settings.NewSignedCommitsManager(logger))

	logger.Debug("Configuration:")
	logger.Debug("  Repository: %s/%s", config.Owner, config.Name)
	logger.Debug("  Default Branch: %s", config.DefaultBranch)
	logger.Debug("  Private: %v", config.Private)
	logger.Debug("  Force Update: %v", config.ForceUpdate)
	logger.Debug("  Debug: %v", config.Debug)
	logger.Debug("  Dry Run: %v", config.DryRun)

	// For existing repos with force update
	if repoExists && config.ForceUpdate {
		logger.Info("Force updating existing repository (security settings will be temporarily disabled)")
		
		// Get current repo info
		repoInfo, err := getRepoInfo(ctx, client, config)
		if err != nil {
			logger.Error("Failed to get repository info: %v", err)
			os.Exit(1)
		}

		// Check and log current settings state
		currentSettings := registry.GetAllValues(ctx, client, *config, repoInfo)
		hasEnabledSettings := false
		for name, value := range currentSettings {
			if value.Enabled {
				logger.Debug("Found enabled setting: %s", name)
				hasEnabledSettings = true
			}
		}

		if hasEnabledSettings {
			logger.Info("Temporarily disabling security settings")
			
			// Create a temporary config with settings disabled
			tempConfig := *config
			tempConfig.ForceUpdate = false // Prevent recursion
			
			// Apply with all settings disabled
			registry.DisableAll(ctx, client, tempConfig, repoInfo)
			
			// Wait briefly for settings to take effect
			time.Sleep(2 * time.Second)
		}
	} else if !repoExists {
		// Create new repository with minimal settings
		repo := &github.Repository{
			Name:          github.Ptr(config.Name),
			Description:   github.Ptr(config.Description),
			Private:       github.Ptr(config.Private),
			DefaultBranch: &config.DefaultBranch,
			AutoInit:      github.Ptr(false),
		}
		_, _, err := client.Repositories.Create(ctx, config.Org, repo)
		if err != nil {
			logger.Error("Failed to create repository: %v", err)
			os.Exit(1)
		}
		logger.Info("Repository created successfully")
	}

	// Get repository info for settings
	repoInfo, err := getRepoInfo(ctx, client, config)
	if err != nil {
		logger.Error("Failed to get repository info: %v", err)
		os.Exit(1)
	}

	// Create/update template files before enabling security settings
	if err := renderAndCreateTemplates(ctx, client, config, logger); err != nil {
		logger.Error("Failed to create template files: %v", err)
		os.Exit(1)
	}

	// Now apply all security settings
	registry.ApplySettings(ctx, client, *config, repoInfo)

	logger.Info("Repository setup completed successfully")
}
