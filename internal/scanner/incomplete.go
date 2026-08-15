package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-github/v90/github"
)

// FactWarning records a fact the scanner could not determine because a GitHub
// request failed for a reason other than a definitive "not found" — a timeout,
// cancellation, rate limit, 5xx, or network error. These are surfaced on
// ScanResult.Incomplete so a partial scan is never silently reported as clean.
//
// The distinction matters because the collectors treat a 404 as a meaningful
// signal ("this config file does not exist"). An indeterminate failure is NOT
// that signal — we simply don't know — and conflating the two would either
// invent findings (e.g. "no update tool") or hide them.
type FactWarning struct {
	Area   string
	Detail string
}

func (w FactWarning) String() string {
	return w.Area + ": " + w.Detail
}

// formatFactWarnings renders warnings as "<area>: <cause>" strings for direct
// rendering across every output mode. Returns nil for no warnings so the
// ScanResult.Incomplete JSON field stays omitted on a complete scan.
func formatFactWarnings(ws []FactWarning) []string {
	if len(ws) == 0 {
		return nil
	}
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.String()
	}
	return out
}

// isNotFound reports whether err is a definitive GitHub 404 — the resource
// genuinely does not exist — as opposed to an indeterminate failure where we
// cannot tell whether it exists.
func isNotFound(err error) bool {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	return false
}

// indeterminate reports whether err means "couldn't determine" rather than a
// clean answer. A nil error (found) or a 404 (definitively absent) is
// determinate; anything else — timeout, cancellation, rate limit, 5xx, network
// error — is not.
func indeterminate(err error) bool {
	return err != nil && !isNotFound(err)
}

// describeFetchError turns an indeterminate fetch error into a short,
// human-readable cause for an incomplete-scan warning. It mirrors the wording
// of classifyGitHubRepoAccessError so the two surfaces read consistently.
func describeFetchError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled before GitHub responded"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out before GitHub responded (raise --timeout)"
	}

	var rateLimitErr *github.RateLimitError
	if errors.As(err, &rateLimitErr) {
		return "GitHub API rate limit exceeded"
	}
	var abuseErr *github.AbuseRateLimitError
	if errors.As(err, &abuseErr) {
		return "GitHub secondary rate limit triggered"
	}

	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return fmt.Sprintf("GitHub returned HTTP %d", ghErr.Response.StatusCode)
	}

	return err.Error()
}
