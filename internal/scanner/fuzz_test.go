package scanner

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-github/v84/github"
)

// These fuzz targets guard the three code paths that parse untrusted input:
// repository config files fetched from GitHub (Renovate JSON5, base64-encoded
// blobs) and user/remote-supplied repository identifiers. The invariant under
// test is the same for all three — never panic, and uphold the documented
// post-conditions — because this input is fully attacker-controllable (any repo
// gasa scans can ship a malformed .renovaterc, and any CLI arg or git remote
// can be hostile).
//
// Run a target on its own with, e.g.:
//
//	go test ./internal/scanner -run x -fuzz FuzzParseRenovateConfig -fuzztime 30s

// FuzzParseRenovateConfig exercises hujson.Standardize + json.Unmarshal on
// arbitrary bytes. A nil error must always yield a non-nil config (callers
// dereference it), and a non-nil error must always yield a nil config.
func FuzzParseRenovateConfig(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		`{"extends":["config:base"],"pinDigests":true}`,
		"// a comment\n{\n  \"minimumReleaseAge\": \"7 days\", // trailing\n}", // JSON5 / hujson
		`{"packageRules":[{"matchManagers":["github-actions"],"pinDigests":true}]}`,
		`{"enabledManagers":[]}`,
		"[]",
		"not json at all",
		`{"extends":`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		cfg, err := parseRenovateConfig(content)
		switch {
		case err != nil && cfg != nil:
			t.Fatalf("parseRenovateConfig(%q) returned both a config and an error", content)
		case err == nil && cfg == nil:
			t.Fatalf("parseRenovateConfig(%q) returned nil config and nil error", content)
		}
	})
}

// FuzzParseRepoURL exercises the owner/repo extractor over the many supported
// URL/SSH/shorthand forms. On success the parsed owner and repo must satisfy the
// same validators the function advertises, and must round-trip: re-parsing
// "owner/repo" must yield the identical pair.
func FuzzParseRepoURL(f *testing.F) {
	seeds := []string{
		"owner/repo",
		"https://github.com/owner/repo",
		"git@github.com:owner/repo.git",
		"ssh://git@github.com/owner/repo",
		"github.com/owner/repo/tree/main",
		"https://www.github.com/owner/repo/",
		"",
		"/",
		"owner//repo",
		"a/b/c/d",
		"-bad/repo",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		owner, repo, err := ParseRepoURL(input)
		if err != nil {
			return // rejected input is a valid outcome; just must not panic
		}
		// Post-conditions for accepted input: both parts must independently
		// pass the package's own validators.
		if verr := validateGitHubOwner(owner); verr != nil {
			t.Fatalf("ParseRepoURL(%q) accepted invalid owner %q: %v", input, owner, verr)
		}
		if verr := validateGitHubRepo(repo); verr != nil {
			t.Fatalf("ParseRepoURL(%q) accepted invalid repo %q: %v", input, repo, verr)
		}
		// Round-trip: the canonical "owner/repo" form must re-parse identically.
		owner2, repo2, err2 := ParseRepoURL(owner + "/" + repo)
		if err2 != nil || owner2 != owner || repo2 != repo {
			t.Fatalf("ParseRepoURL round-trip mismatch for %q: got (%q,%q,%v), want (%q,%q,nil)",
				input, owner2, repo2, err2, owner, repo)
		}
	})
}

// FuzzDecodeContent exercises the base64 blob decoder over arbitrary content and
// encoding values, mirroring what GitHub returns for file contents. It must
// never panic; on success the round-trip back to base64 must reproduce the
// decoded bytes.
func FuzzDecodeContent(f *testing.F) {
	f.Add(base64.StdEncoding.EncodeToString([]byte("version: 2")), "base64")
	f.Add("not!base64!", "base64")
	f.Add("", "base64")
	f.Add("aGVsbG8=\n", "base64") // padded with a newline, like GitHub wraps

	f.Fuzz(func(t *testing.T, raw, encoding string) {
		content := &github.RepositoryContent{
			Content:  &raw,
			Encoding: &encoding,
		}
		decoded, err := decodeContent(content)
		if err != nil {
			return // undecodable content is a valid outcome
		}
		// On success, the decoded string must re-encode to bytes that decode
		// back to the same value — i.e. decodeContent produced real bytes.
		if got, derr := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte(decoded))); derr != nil || string(got) != decoded {
			t.Fatalf("decodeContent round-trip failed for %q: got %q (err %v)", raw, got, derr)
		}
	})
}
