package auth

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	applog "gh-secure-template-repo/internal/log"
)

// AuthSource describes where the token came from.
type AuthSource string

const (
	SourceDeviceFlow AuthSource = "device flow (OAuth)"
	SourceEnvVar     AuthSource = "GITHUB_TOKEN env"
	SourceCached     AuthSource = "cached token"
)

// AuthResult holds the resolved token and its source.
type AuthResult struct {
	Token  string
	Source AuthSource
}

// ResolveToken determines the token to use based on precedence:
//  1. --login flag: run device flow, cache token, return it
//  2. GITHUB_TOKEN env var
//  3. Cached token from ~/.config/gh-secure/token.json
//  4. Error with instructions
func ResolveToken(logger applog.Logger, clientID string, forceLogin bool) (*AuthResult, error) {
	store, err := NewTokenStore()
	if err != nil {
		return nil, err
	}

	// 1. Interactive login via device flow.
	if forceLogin {
		if clientID == "" {
			return nil, fmt.Errorf("--client-id is required for --login (register an OAuth App at https://github.com/settings/developers)")
		}

		token, err := runDeviceFlow(logger, clientID)
		if err != nil {
			return nil, fmt.Errorf("device flow failed: %w", err)
		}

		if err := store.Save(token); err != nil {
			logger.Warn("Failed to cache token: %v", err)
		} else {
			logger.Info("Token cached to %s", store.Path())
		}

		return &AuthResult{Token: token.AccessToken, Source: SourceDeviceFlow}, nil
	}

	// 2. GITHUB_TOKEN environment variable.
	if envToken := os.Getenv("GITHUB_TOKEN"); envToken != "" {
		return &AuthResult{Token: envToken, Source: SourceEnvVar}, nil
	}

	// 3. Cached token from filesystem.
	cached, err := store.Load()
	if err != nil {
		logger.Warn("Error reading cached token: %v", err)
	}
	if cached != nil {
		return &AuthResult{Token: cached.AccessToken, Source: SourceCached}, nil
	}

	// 4. No token available.
	return nil, fmt.Errorf("no authentication token found\n\n" +
		"  Options:\n" +
		"    1. Set GITHUB_TOKEN environment variable\n" +
		"    2. Run: gh-secure --login --client-id <YOUR_OAUTH_APP_CLIENT_ID>\n" +
		"    3. Run: export GITHUB_TOKEN=$(gh auth token)\n")
}

// Logout clears the cached token.
func Logout(logger applog.Logger) error {
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	if err := store.Clear(); err != nil {
		return err
	}
	logger.Info("Cached token removed from %s", store.Path())
	return nil
}

const (
	githubTokenSettingsURL = "https://github.com/settings/tokens"
	githubOAuthAppsURL     = "https://github.com/settings/applications"
)

// Revoke clears the local cached token and opens the browser to GitHub's
// token management page so the user can revoke server-side.
func Revoke(logger applog.Logger) error {
	// 1. Clear local cache.
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	cached, _ := store.Load()
	if cached != nil {
		if err := store.Clear(); err != nil {
			logger.Warn("Failed to clear cached token: %v", err)
		} else {
			logger.Info("Local cached token cleared from %s", store.Path())
		}
	}

	// 2. Inform the user and open browser.
	fmt.Println()
	fmt.Println("  To revoke your token on GitHub, visit one of:")
	fmt.Println()
	fmt.Printf("    PATs:        %s\n", githubTokenSettingsURL)
	fmt.Printf("    OAuth Apps:  %s\n", githubOAuthAppsURL)
	fmt.Println()
	fmt.Println("  Opening GitHub token settings in your browser...")
	fmt.Println()

	if err := openBrowser(githubTokenSettingsURL); err != nil {
		logger.Warn("Could not open browser: %v", err)
		logger.Info("Please open the URL above manually.")
	}

	// 3. Remind about env var.
	if os.Getenv("GITHUB_TOKEN") != "" {
		logger.Warn("GITHUB_TOKEN is still set in your environment. Run: unset GITHUB_TOKEN")
	}

	return nil
}

// openBrowser opens the given URL in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}

// runDeviceFlow executes the interactive device flow and returns a token.
func runDeviceFlow(logger applog.Logger, clientID string) (*TokenResponse, error) {
	dc, err := RequestDeviceCode(clientID, DefaultScopes)
	if err != nil {
		return nil, err
	}

	// Display instructions to the user.
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Printf("  │  Open:  %-40s │\n", dc.VerificationURI)
	fmt.Printf("  │  Code:  %-40s │\n", dc.UserCode)
	fmt.Println("  │                                                  │")
	fmt.Println("  │  Waiting for authorization...                    │")
	fmt.Println("  └──────────────────────────────────────────────────┘")
	fmt.Println()

	token, err := PollForToken(clientID, dc)
	if err != nil {
		return nil, err
	}

	logger.Info("Authorization successful")
	return token, nil
}
