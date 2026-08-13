package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v90/github"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRetryTransportRetriesTransientGETResponses(t *testing.T) {
	calls := 0
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return testResponse(req, http.StatusBadGateway, nil), nil
		}
		return testResponse(req, http.StatusOK, nil), nil
	})

	resp, err := transport.RoundTrip(testRequest(t, http.MethodGet))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestRetryTransportDoesNotRetryPermanentResponses(t *testing.T) {
	calls := 0
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return testResponse(req, http.StatusNotFound, nil), nil
	})

	resp, err := transport.RoundTrip(testRequest(t, http.MethodGet))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestRetryTransportDoesNotRetryNonIdempotentMethods(t *testing.T) {
	calls := 0
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		return testResponse(req, http.StatusServiceUnavailable, nil), nil
	})

	resp, err := transport.RoundTrip(testRequest(t, http.MethodPost))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestRetryTransportHonorsRetryAfter(t *testing.T) {
	var slept []time.Duration
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		if len(slept) == 0 {
			return testResponse(req, http.StatusTooManyRequests, http.Header{"Retry-After": []string{"3"}}), nil
		}
		return testResponse(req, http.StatusOK, nil), nil
	})
	transport.sleep = func(_ context.Context, delay time.Duration) error {
		slept = append(slept, delay)
		return nil
	}

	_, err := transport.RoundTrip(testRequest(t, http.MethodGet))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if len(slept) != 1 || slept[0] != 3*time.Second {
		t.Fatalf("slept = %v, want [3s]", slept)
	}
}

func TestRetryTransportHonorsPrimaryRateLimitReset(t *testing.T) {
	now := time.Unix(100, 0)
	var slept []time.Duration
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		if len(slept) == 0 {
			return testResponse(req, http.StatusForbidden, http.Header{
				"X-Ratelimit-Remaining": []string{"0"},
				"X-Ratelimit-Reset":     []string{"105"},
			}), nil
		}
		return testResponse(req, http.StatusOK, nil), nil
	})
	transport.now = func() time.Time { return now }
	transport.sleep = func(_ context.Context, delay time.Duration) error {
		slept = append(slept, delay)
		return nil
	}

	_, err := transport.RoundTrip(testRequest(t, http.MethodGet))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if len(slept) != 1 || slept[0] != 5*time.Second {
		t.Fatalf("slept = %v, want [5s]", slept)
	}
}

func TestRetryTransportLimitsConcurrentRequests(t *testing.T) {
	const limit = 2

	var (
		mu       sync.Mutex
		inFlight int
		maxSeen  int
	)
	release := make(chan struct{})

	transport := newRetryTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		inFlight++
		if inFlight > maxSeen {
			maxSeen = inFlight
		}
		mu.Unlock()

		<-release // hold the in-flight slot until the test releases all requests

		mu.Lock()
		inFlight--
		mu.Unlock()
		return testResponse(req, http.StatusOK, nil), nil
	}))
	transport.sem = make(chan struct{}, limit)

	const requests = 6
	var wg sync.WaitGroup
	wg.Add(requests)
	for range requests {
		go func() {
			defer wg.Done()
			resp, err := transport.RoundTrip(testRequest(t, http.MethodGet))
			if err != nil {
				return
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// Wait until the semaphore is saturated, then let everything proceed.
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		seen := maxSeen
		mu.Unlock()
		if seen >= limit {
			break
		}
		select {
		case <-deadline:
			close(release)
			wg.Wait()
			t.Fatalf("never reached %d concurrent in-flight requests (maxSeen=%d)", limit, seen)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	wg.Wait()

	if maxSeen > limit {
		t.Fatalf("max concurrent in-flight = %d, want <= %d", maxSeen, limit)
	}
}

func TestRetryTransportHoldsSlotUntilBodyClose(t *testing.T) {
	transport := newTestRetryTransport(func(req *http.Request) (*http.Response, error) {
		return testResponse(req, http.StatusOK, nil), nil
	})
	transport.sem = make(chan struct{}, 1)

	resp, err := transport.RoundTrip(testRequest(t, http.MethodGet))
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}

	// The single slot must still be held while the response body is open.
	select {
	case transport.sem <- struct{}{}:
		t.Fatal("slot released before response body was closed")
	default:
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Body.Close() error = %v", err)
	}

	// Closing the body must free the slot, and closing again must not free it twice.
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("second Body.Close() error = %v", err)
	}
	transport.sem <- struct{}{} // would block/panic on a double release
	select {
	case transport.sem <- struct{}{}:
		t.Fatal("slot released more than once")
	default:
	}
}

// TestRetryTransportReleasesSlotOnErrorResponse is a regression test for a
// semaphore-slot leak on error responses. go-github's CheckResponse drains an
// error body (404, 422, rate limits, …) with io.ReadAll and then REPLACES
// resp.Body with an io.NopCloser so the error payload can be re-read. The
// deferred Close in go-github's bareDo therefore closes that NopCloser, never
// our releaseOnClose wrapper — so releasing the in-flight slot on Close alone
// leaks one slot per error response. The renovate collector probes ~9 missing
// config paths (all 404), exhausts the cap, and every later request blocks on
// acquire until the per-repo context deadline ("context deadline exceeded").
//
// With a cap of 2 and more error responses than the cap, a leak deadlocks: once
// both slots leak, the next acquire blocks until its context deadline. The fix
// also releases on EOF, which go-github's ReadAll triggers, so this completes.
func TestRetryTransportReleasesSlotOnErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := io.WriteString(w, `{"message":"Not Found"}`); err != nil {
			t.Errorf("writing response body: %v", err)
		}
	}))
	defer srv.Close()

	transport := &retryTransport{
		base:        http.DefaultTransport,
		maxAttempts: defaultRetryMaxAttempts,
		baseDelay:   time.Nanosecond,
		now:         time.Now,
		sleep:       sleepWithContext,
		sem:         make(chan struct{}, 2),
	}
	base := srv.URL + "/"
	client, err := github.NewClient(
		github.WithHTTPClient(&http.Client{Transport: transport}),
		github.WithURLs(&base, nil),
	)
	if err != nil {
		t.Fatalf("github.NewClient() error = %v", err)
	}

	// More requests than the slot cap. A per-call deadline turns a regression
	// into a deterministic, fast failure rather than a hung test.
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _, _, err := client.Repositories.GetContents(ctx, "owner", "repo", "renovate.json", nil)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request %d blocked on the in-flight semaphore (leaked slot): %v", i+1, err)
		}
		var ghErr *github.ErrorResponse
		if !errors.As(err, &ghErr) || ghErr.Response.StatusCode != http.StatusNotFound {
			t.Fatalf("request %d error = %v, want 404 ErrorResponse", i+1, err)
		}
	}
}

func newTestRetryTransport(fn func(*http.Request) (*http.Response, error)) *retryTransport {
	transport := newRetryTransport(roundTripFunc(fn))
	transport.baseDelay = time.Nanosecond
	transport.sleep = func(context.Context, time.Duration) error { return nil }
	return transport
}

func testRequest(t *testing.T, method string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "https://api.github.test/repos/owner/repo", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	return req
}

func testResponse(req *http.Request, status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}
}
