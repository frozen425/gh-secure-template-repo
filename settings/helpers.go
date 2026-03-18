package settings

import (
	"github.com/google/go-github/v68/github"
)

// protectionToRequest converts an existing Protection response into a
// ProtectionRequest that can be used with UpdateBranchProtection.
// This preserves existing settings so that toggling one field (e.g.
// AllowForcePushes) does not reset others.
func protectionToRequest(p *github.Protection) *github.ProtectionRequest {
	req := &github.ProtectionRequest{}

	if p == nil {
		return req
	}

	// Required status checks.
	if sc := p.GetRequiredStatusChecks(); sc != nil {
		req.RequiredStatusChecks = &github.RequiredStatusChecks{
			Strict: sc.Strict,
			Checks: sc.Checks,
		}
	}

	// Enforce admins.
	if ea := p.GetEnforceAdmins(); ea != nil {
		req.EnforceAdmins = ea.Enabled
	}

	// Required pull request reviews.
	if pr := p.GetRequiredPullRequestReviews(); pr != nil {
		rr := &github.PullRequestReviewsEnforcementRequest{
			RequiredApprovingReviewCount: pr.RequiredApprovingReviewCount,
			DismissStaleReviews:         pr.DismissStaleReviews,
			RequireCodeOwnerReviews:     pr.RequireCodeOwnerReviews,
		}
		req.RequiredPullRequestReviews = rr
	}

	// Restrictions (nil means no restrictions).
	// We pass an empty request to preserve the "no restrictions" state.

	// AllowForcePushes / AllowDeletions are set by the caller.

	return req
}
