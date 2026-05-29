package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
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
