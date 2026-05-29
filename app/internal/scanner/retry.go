package scanner

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/go-github/v84/github"
)

const (
	defaultRetryMaxAttempts = 2
	defaultRetryBaseDelay   = 250 * time.Millisecond
)

type retryTransport struct {
	base        http.RoundTripper
	maxAttempts int
	baseDelay   time.Duration
	now         func() time.Time
	sleep       func(context.Context, time.Duration) error
}

func newGitHubClient() *github.Client {
	return github.NewClient(&http.Client{Transport: newRetryTransport(http.DefaultTransport)})
}

func newRetryTransport(base http.RoundTripper) *retryTransport {
	return &retryTransport{
		base:        base,
		maxAttempts: defaultRetryMaxAttempts,
		baseDelay:   defaultRetryBaseDelay,
		now:         time.Now,
		sleep:       sleepWithContext,
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !retryableMethod(req.Method) {
		return t.base.RoundTrip(req)
	}

	for attempt := 0; ; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if err != nil || !t.shouldRetry(resp) || attempt >= t.maxAttempts {
			return resp, err
		}

		closeResponseBody(resp)
		if err := t.sleep(req.Context(), t.retryDelay(resp, attempt)); err != nil {
			return nil, err
		}
	}
}

func retryableMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func (t *retryTransport) shouldRetry(resp *http.Response) bool {
	if resp == nil {
		return false
	}

	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		return isPrimaryRateLimitResponse(resp)
	default:
		return false
	}
}

func (t *retryTransport) retryDelay(resp *http.Response, attempt int) time.Duration {
	if delay, ok := parseRetryAfter(resp.Header.Get("Retry-After"), t.now()); ok {
		return delay
	}
	if isPrimaryRateLimitResponse(resp) {
		if delay, ok := parseRateLimitReset(resp.Header.Get("X-RateLimit-Reset"), t.now()); ok {
			return delay
		}
	}
	return t.baseDelay << attempt
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return nonNegativeDuration(when.Sub(now)), true
}

func parseRateLimitReset(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return nonNegativeDuration(time.Unix(seconds, 0).Sub(now)), true
}

func nonNegativeDuration(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

func closeResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	// Drain and discard the response body before closing to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // intentionally draining and discarding
	_ = resp.Body.Close()
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
