package settings

import (
	"context"
	"strings"

	"github.com/google/go-github/v68/github"
)

// TokenCapabilities captures the permissions and plan info of the authenticated token.
type TokenCapabilities struct {
	Login         string
	Scopes        []string // parsed from X-OAuth-Scopes header
	IsFineGrained bool     // true when classic scopes header is absent
	PlanName      string   // user billing plan (free / pro / etc.)
	OrgPlan       string   // org billing plan if applicable
	IsPro         bool     // derived from plan
	IsEnterprise  bool     // derived from plan
}

// HasScope returns true if the token has the given OAuth scope (or a parent
// scope that implies it).  For fine-grained PATs this always returns true
// because scope information is not available — individual API calls will
// return 403 if the permission is missing, and the caller should handle that.
func (t *TokenCapabilities) HasScope(scope string) bool {
	if t.IsFineGrained {
		return true // cannot pre-screen; rely on per-call errors
	}
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
		// "repo" implies all repo sub-scopes
		if s == "repo" && strings.HasPrefix(scope, "repo") {
			return true
		}
		// "admin:repo_hook" implies "write:repo_hook" and "read:repo_hook"
		if s == "admin:repo_hook" && (scope == "write:repo_hook" || scope == "read:repo_hook") {
			return true
		}
		// "admin:org" implies read:org and write:org
		if s == "admin:org" && (scope == "read:org" || scope == "write:org") {
			return true
		}
	}
	return false
}

// DetectTokenCapabilities makes an authenticated /user call, inspects the
// response headers for OAuth scopes, and queries plan information.
func DetectTokenCapabilities(ctx context.Context, client *github.Client, org string) (*TokenCapabilities, error) {
	user, resp, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, err
	}

	caps := &TokenCapabilities{
		Login: user.GetLogin(),
	}

	// Parse scopes from the response header (classic PATs only).
	if raw := resp.Header.Get("X-OAuth-Scopes"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				caps.Scopes = append(caps.Scopes, s)
			}
		}
	} else {
		caps.IsFineGrained = true
	}

	// Derive plan info from the authenticated user.
	if plan := user.GetPlan(); plan != nil {
		caps.PlanName = plan.GetName()
	}
	caps.IsPro = caps.PlanName == "pro" || caps.PlanName == "team"
	caps.IsEnterprise = caps.PlanName == "enterprise"

	// If an org was supplied, try to fetch the org-level plan.
	if org != "" {
		orgObj, _, err := client.Organizations.Get(ctx, org)
		if err == nil && orgObj.GetPlan() != nil {
			caps.OrgPlan = orgObj.GetPlan().GetName()
			if caps.OrgPlan == "enterprise" {
				caps.IsEnterprise = true
			}
			if caps.OrgPlan == "team" || caps.OrgPlan == "enterprise" {
				caps.IsPro = true
			}
		}
		// Non-fatal: we still proceed if we can't read the org.
	}

	return caps, nil
}
