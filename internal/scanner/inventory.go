package scanner

import (
	"context"
	"fmt"

	"github.com/google/go-github/v84/github"
)

// fileInventory records which files exist at the repository root and inside the
// .github/ and .gitlab/ directories — the only three places the Dependabot and
// Renovate collectors ever look.
//
// Why it exists: the collectors used to probe every candidate config path with
// its own GET, and a repository *without* Renovate — the common case — paid all
// nine 404s on every scan. With Dependabot's two probes that was 11 requests to
// establish absence. Listing the three directories answers the same question in
// at most three requests (usually one or two, since .gitlab/ is only listed
// when the root shows it exists), which matters for batch scans: at ~19 calls
// per repo, an authenticated 5,000/hour budget capped batch runs near 260
// repos/hour, with nearly half the budget spent proving files absent.
type fileInventory struct {
	// Complete reports whether the listings fully answered "which files exist".
	// When false the collectors fall back to per-path probing, so a listing
	// failure can only cost speed, never correctness.
	Complete bool

	paths map[string]bool
}

// Has reports whether the listing saw the given path. Only meaningful when
// Complete is true.
func (inv fileInventory) Has(path string) bool {
	return inv.paths[path]
}

// probeEverything is the zero-value inventory: incomplete, so every consumer
// probes each path individually. It is the explicit fallback for listing
// failures and the fixture for tests that exercise the probing code path.
func probeEverything() fileInventory {
	return fileInventory{}
}

// inventoryDirs are the directories the update-tool collectors care about. The
// root is always listed; the dot-directories only when the root listing shows
// them, which keeps the common case at two requests and a bare repository at
// one.
var inventoryDirs = []string{".github", ".gitlab"}

// Entry types in a contents-API directory listing.
const (
	entryTypeFile = "file"
	entryTypeDir  = "dir"
)

// contentsListingCap is the GitHub contents API's per-directory limit. A
// directory with more entries is silently truncated, so a listing that returns
// exactly this many entries cannot prove absence and the inventory falls back
// to probing.
const contentsListingCap = 1000

// collectFileInventory lists the repository root and any relevant
// dot-directories. Every failure mode degrades to probeEverything rather than
// guessing: a wrong "absent" here would make the update-tool rules report a
// missing config that exists, which is a false finding invented from a
// transport problem.
func (c *factCollector) collectFileInventory(ctx context.Context, owner, repo string, dbg DebugLogger) fileInventory {
	repoFull := owner + "/" + repo
	inv := fileInventory{paths: make(map[string]bool)}

	rootEntries, ok := c.listDirectory(ctx, owner, repo, "", repoFull, dbg)
	if !ok {
		return probeEverything()
	}

	dirs := make(map[string]bool)
	for _, entry := range rootEntries {
		switch entry.GetType() {
		case entryTypeFile:
			inv.paths[entry.GetName()] = true
		case entryTypeDir:
			dirs[entry.GetName()] = true
		}
	}

	for _, dir := range inventoryDirs {
		if !dirs[dir] {
			continue
		}
		entries, ok := c.listDirectory(ctx, owner, repo, dir, repoFull, dbg)
		if !ok {
			return probeEverything()
		}
		for _, entry := range entries {
			if entry.GetType() == entryTypeFile {
				inv.paths[dir+"/"+entry.GetName()] = true
			}
		}
	}

	inv.Complete = true
	if dbg != nil {
		dbg(repoFull, fmt.Sprintf("file inventory complete: %d files across root and dot-directories", len(inv.paths)))
	}
	return inv
}

// listDirectory returns a directory's entries and whether the answer is
// trustworthy. A 404 is a trustworthy "directory does not exist" (including the
// empty-repository case for the root); an error or a listing at the API's
// truncation cap is not.
func (c *factCollector) listDirectory(ctx context.Context, owner, repo, dir, repoFull string, dbg DebugLogger) ([]*github.RepositoryContent, bool) {
	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+dir+" (listing)")
	}
	_, entries, _, err := c.client.Repositories.GetContents(ctx, owner, repo, dir, nil)
	switch {
	case isNotFound(err):
		return nil, true
	case err != nil:
		if dbg != nil {
			dbg(repoFull, "listing "+dir+" failed ("+describeFetchError(err)+") — falling back to per-path probing")
		}
		return nil, false
	case len(entries) >= contentsListingCap:
		// Cannot distinguish "exactly at the cap" from "truncated", so treat the
		// whole inventory as unusable rather than risk a false "absent".
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("listing %s returned %d entries (API cap) — falling back to per-path probing", dir, len(entries)))
		}
		return nil, false
	}
	return entries, true
}
