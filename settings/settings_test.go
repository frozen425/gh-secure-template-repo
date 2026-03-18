package settings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v68/github"
)

// newTestClient creates a *github.Client backed by the given handler.
func newTestClient(t *testing.T, handler http.Handler) *github.Client {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)

	client := github.NewClient(nil)
	baseURL, _ := client.BaseURL.Parse(s.URL + "/")
	client.BaseURL = baseURL
	return client
}

// ---------------------------------------------------------------------------
// Token capabilities
// ---------------------------------------------------------------------------

func TestDetectTokenCapabilities_ClassicPAT(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org, admin:repo_hook")
		json.NewEncoder(w).Encode(&github.User{
			Login: github.Ptr("testuser"),
			Plan: &github.Plan{
				Name: github.Ptr("pro"),
			},
		})
	})

	client := newTestClient(t, mux)
	caps, err := DetectTokenCapabilities(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if caps.Login != "testuser" {
		t.Errorf("login = %q, want %q", caps.Login, "testuser")
	}
	if caps.IsFineGrained {
		t.Error("expected classic PAT, got fine-grained")
	}
	if !caps.IsPro {
		t.Error("expected IsPro=true for pro plan")
	}
	if !caps.HasScope("repo") {
		t.Error("expected HasScope('repo')=true")
	}
	if !caps.HasScope("read:org") {
		t.Error("expected HasScope('read:org')=true")
	}
	// "repo" implies repo sub-scopes.
	if !caps.HasScope("repo:status") {
		t.Error("expected HasScope('repo:status')=true (implied by repo)")
	}
	if caps.HasScope("delete_repo") {
		t.Error("expected HasScope('delete_repo')=false")
	}
}

func TestDetectTokenCapabilities_FineGrained(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		// Fine-grained PATs do not emit X-OAuth-Scopes header.
		json.NewEncoder(w).Encode(&github.User{
			Login: github.Ptr("fguser"),
			Plan: &github.Plan{
				Name: github.Ptr("free"),
			},
		})
	})

	client := newTestClient(t, mux)
	caps, err := DetectTokenCapabilities(context.Background(), client, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !caps.IsFineGrained {
		t.Error("expected fine-grained PAT")
	}
	// Fine-grained tokens always return true from HasScope.
	if !caps.HasScope("anything") {
		t.Error("expected HasScope to return true for fine-grained PAT")
	}
	if caps.IsPro {
		t.Error("expected IsPro=false for free plan")
	}
}

// ---------------------------------------------------------------------------
// Registry: AssessAll
// ---------------------------------------------------------------------------

func TestAssessAll_SkipsInsufficientScopes(t *testing.T) {
	// Token with NO scopes (classic PAT, empty scopes).
	caps := &TokenCapabilities{Login: "u", Scopes: []string{}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)

	registry.RegisterSetting("signed_commits", NewSignedCommitsManager())

	mux := http.NewServeMux()
	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main"}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusSkipped {
		t.Errorf("expected SKIP, got %s", results[0].Status)
	}
}

func TestAssessAll_PassWhenEnabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&github.Protection{
			RequiredSignatures: &github.SignaturesProtectedBranch{
				Enabled: github.Ptr(true),
			},
		})
	})

	caps := &TokenCapabilities{Login: "u", Scopes: []string{"repo"}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)
	registry.RegisterSetting("signed_commits", NewSignedCommitsManager())

	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main"}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusPass {
		t.Errorf("expected PASS, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

func TestAssessAll_FailWhenDisabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&github.Protection{
			RequiredSignatures: &github.SignaturesProtectedBranch{
				Enabled: github.Ptr(false),
			},
		})
	})

	caps := &TokenCapabilities{Login: "u", Scopes: []string{"repo"}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)
	registry.RegisterSetting("signed_commits", NewSignedCommitsManager())

	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main"}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if results[0].Status != StatusFail {
		t.Errorf("expected FAIL, got %s", results[0].Status)
	}
}

func TestAssessAll_NoBranchProtection404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	caps := &TokenCapabilities{Login: "u", Scopes: []string{"repo"}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)
	registry.RegisterSetting("branch_protection", NewBranchProtectionManager())

	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main"}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if results[0].Status != StatusFail {
		t.Errorf("expected FAIL for missing branch protection, got %s", results[0].Status)
	}
}

// ---------------------------------------------------------------------------
// Vulnerability alerts
// ---------------------------------------------------------------------------

func TestVulnerabilityAlerts_Enabled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/vulnerability-alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 204 = enabled
	})

	caps := &TokenCapabilities{Login: "u", Scopes: []string{"repo"}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)
	registry.RegisterSetting("vulnerability_alerts", NewVulnerabilityAlertsManager())

	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main"}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if results[0].Status != StatusPass {
		t.Errorf("expected PASS for enabled vuln alerts, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// Secret scanning availability gating
// ---------------------------------------------------------------------------

func TestSecretScanning_SkippedForPrivateNonEnterprise(t *testing.T) {
	caps := &TokenCapabilities{Login: "u", Scopes: []string{"repo"}}
	logger := &nopLogger{}
	registry := NewSecuritySettingsRegistry(logger, caps)
	registry.RegisterSetting("secret_scanning", NewSecretScanningManager())

	mux := http.NewServeMux()
	client := newTestClient(t, mux)
	info := &RepoInfo{DefaultBranch: "main", IsPrivate: true, IsEnterprise: false}

	results := registry.AssessAll(context.Background(), client, Config{Owner: "o", Name: "r"}, info)
	if results[0].Status != StatusSkipped {
		t.Errorf("expected SKIP for private non-enterprise repo, got %s (%s)", results[0].Status, results[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// nopLogger for tests
// ---------------------------------------------------------------------------

type nopLogger struct{}

func (l *nopLogger) Debug(format string, args ...interface{}) {}
func (l *nopLogger) Info(format string, args ...interface{})  {}
func (l *nopLogger) Warn(format string, args ...interface{})  {}
func (l *nopLogger) Error(format string, args ...interface{}) {}
