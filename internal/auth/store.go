package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const configDirName = "gh-secure"

// CachedToken is the structure persisted to disk.
type CachedToken struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Scope       string    `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
}

// TokenStore manages reading and writing tokens to the filesystem.
type TokenStore struct {
	dir string
}

// NewTokenStore creates a store rooted at ~/.config/gh-secure/.
func NewTokenStore() (*TokenStore, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine config directory: %w", err)
	}
	dir := filepath.Join(configDir, configDirName)
	return &TokenStore{dir: dir}, nil
}

func (s *TokenStore) tokenPath() string {
	return filepath.Join(s.dir, "token.json")
}

// Save persists a token to disk with restrictive permissions.
func (s *TokenStore) Save(token *TokenResponse) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	cached := CachedToken{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		Scope:       token.Scope,
		CreatedAt:   time.Now(),
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	if err := os.WriteFile(s.tokenPath(), data, 0600); err != nil {
		return fmt.Errorf("writing token file: %w", err)
	}

	return nil
}

// Load reads a cached token from disk. Returns nil if no token is cached.
func (s *TokenStore) Load() (*CachedToken, error) {
	data, err := os.ReadFile(s.tokenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading token file: %w", err)
	}

	var cached CachedToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, fmt.Errorf("parsing token file: %w", err)
	}

	if cached.AccessToken == "" {
		return nil, nil
	}

	return &cached, nil
}

// Clear removes the cached token.
func (s *TokenStore) Clear() error {
	err := os.Remove(s.tokenPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing token file: %w", err)
	}
	return nil
}

// Path returns the token file path (for display purposes).
func (s *TokenStore) Path() string {
	return s.tokenPath()
}
