package scanner

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-github/v90/github"
)

const (
	defaultRetryMaxAttempts = 2
	defaultRetryBaseDelay   = 250 * time.Millisecond

	// defaultMaxInFlight caps how many requests this client has outstanding at
	// once. Per-repo fan-out (concurrent collectors + workflow fetches) multiplied
	// by batch-level repo concurrency can otherwise burst into GitHub's secondary
	// (abuse) rate limit, which throttles clients that open too many simultaneous
	// connections. Bounding it at the transport keeps every call path safe without
	// each caller having to coordinate.
	defaultMaxInFlight = 8
)

type retryTransport struct {
	base        http.RoundTripper
	maxAttempts int
	baseDelay   time.Duration
	now         func() time.Time
	sleep       func(context.Context, time.Duration) error
	// sem bounds concurrent in-flight requests. A nil sem disables the limit
	// (used by unit tests that drive RoundTrip directly).
	sem chan struct{}
}

// newGitHubClient builds the shared client: our retrying, concurrency-bounded
// transport plus any extra options (an auth token, in practice).
//
// go-github v90 moved to functional options and NewClient now returns an
// error. Every failure mode is a programmer error at this call site — a nil
// HTTP client or an empty auth token, both of which the callers below make
// impossible — so this panics rather than threading an error through New and
// NewWithToken signatures that the CLI relies on.
func newGitHubClient(extra ...github.ClientOptionsFunc) *github.Client {
	opts := append([]github.ClientOptionsFunc{
		github.WithHTTPClient(&http.Client{Transport: newRetryTransport(http.DefaultTransport)}),
	}, extra...)
	client, err := github.NewClient(opts...)
	if err != nil {
		panic("constructing GitHub client: " + err.Error())
	}
	return client
}

func newRetryTransport(base http.RoundTripper) *retryTransport {
	return &retryTransport{
		base:        base,
		maxAttempts: defaultRetryMaxAttempts,
		baseDelay:   defaultRetryBaseDelay,
		now:         time.Now,
		sleep:       sleepWithContext,
		sem:         make(chan struct{}, defaultMaxInFlight),
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Acquire an in-flight slot for the whole request lifetime, including any
	// retry backoff and the time the caller spends reading the response body.
	// http.RoundTrip returns once the response headers arrive while the body is
	// still streaming on the connection, so the slot is released from the body's
	// Close rather than here. Respect cancellation so a dead context doesn't
	// block on a full semaphore.
	release := func() {}
	if t.sem != nil {
		select {
		case t.sem <- struct{}{}:
			var once sync.Once
			release = func() { once.Do(func() { <-t.sem }) }
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	resp, err := t.roundTrip(req)

	// With no body for the caller to close, release the slot immediately;
	// otherwise hand it off to the body wrapper so the cap reflects the full
	// connection lifetime.
	if err != nil || resp == nil || resp.Body == nil {
		release()
		return resp, err
	}
	resp.Body = &releaseOnClose{ReadCloser: resp.Body, release: release}
	return resp, nil
}

func (t *retryTransport) roundTrip(req *http.Request) (*http.Response, error) {
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

// releaseOnClose releases the in-flight semaphore slot when the wrapped response
// body is fully read (EOF) or closed, whichever happens first, so the concurrency
// cap covers the full request lifetime rather than ending when RoundTrip returns
// at the response headers.
//
// Releasing on EOF — not just Close — is required because go-github's
// CheckResponse drains error responses (404, 422, rate limits, …) with
// io.ReadAll and then REPLACES resp.Body with an io.NopCloser so callers can
// re-read the error payload. The deferred Close in go-github's bareDo therefore
// closes that NopCloser, never this wrapper, so a Close-only release would leak
// a slot on every error response. Reading to EOF still flows through this
// wrapper's Read, so that path releases the slot. release is idempotent (guarded
// by a sync.Once in RoundTrip), so firing on both EOF and a later Close is safe.
type releaseOnClose struct {
	io.ReadCloser
	release func()
}

func (r *releaseOnClose) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err != nil {
		// Per the io.Reader contract a non-nil error (io.EOF or a terminal read
		// error) means the body is done streaming; release the slot now in case
		// the caller never calls Close on this wrapper.
		r.release()
	}
	return n, err
}

func (r *releaseOnClose) Close() error {
	defer r.release()
	return r.ReadCloser.Close()
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
