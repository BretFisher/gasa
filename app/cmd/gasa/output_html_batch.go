package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bretfisher/github-security-assessment/app/internal/scanner"
)

// htmlBatchRepoEntry is the view model for a single repo in the batch report.
type htmlBatchRepoEntry struct {
	RepoFullName string
	Anchor       string // URL-safe anchor for sidebar nav
	StateClass   string // "clean", "findings", "error"
	Counts       []string
	Successes    int
	HasError     bool
	ErrorMsg     string
	Findings     []htmlFindingView
}

// htmlBatchView is the top-level view model for the combined batch report.
type htmlBatchView struct {
	ScannedAt   string
	TotalRepos  int
	StateCounts map[string]int // count of repos in each state class
	Repos       []htmlBatchRepoEntry
}

// repoAnchor converts "owner/repo" into a safe HTML anchor id.
func repoAnchor(repoFull string) string {
	return strings.ReplaceAll(repoFull, "/", "-")
}

// repoStateClass returns the 4-state CSS class for sidebar coloring.
//
//	"error"         — scan failed entirely or returned a result-level error
//	"high-findings" — scan succeeded and has one or more HIGH or CRITICAL severity findings
//	"findings"      — scan succeeded but has one or more non-success findings (medium/low/info)
//	"clean"         — scan succeeded with zero findings
func repoStateClass(r batchRepoResult) string {
	if r.Err != nil {
		return stateClassError
	}
	if r.Result != nil && r.Result.Error != "" {
		return stateClassError
	}
	if r.Result != nil {
		hasHighOrCritical := false
		hasFindings := false
		for _, f := range r.Result.Findings {
			if !f.Success {
				hasFindings = true
				if f.Severity == scanner.SeverityHigh || f.Severity == scanner.SeverityCritical {
					hasHighOrCritical = true
					break // Found high/critical, no need to continue
				}
			}
		}
		if hasHighOrCritical {
			return stateClassHighFindings
		}
		if hasFindings {
			return stateClassFindings
		}
	}
	return stateClassClean
}

// buildBatchView converts raw batchRepoResults into the HTML view model.
func buildBatchView(results []batchRepoResult) htmlBatchView {
	stateCounts := map[string]int{
		stateClassClean:        0,
		stateClassFindings:     0,
		stateClassHighFindings: 0,
		stateClassError:        0,
	}
	entries := make([]htmlBatchRepoEntry, 0, len(results))

	for _, r := range results {
		entry := htmlBatchRepoEntry{
			RepoFullName: r.RepoFullName,
			Anchor:       repoAnchor(r.RepoFullName),
			StateClass:   repoStateClass(r),
		}

		switch {
		case r.Err != nil:
			entry.HasError = true
			entry.ErrorMsg = r.Err.Error()
		case r.Result != nil && r.Result.Error != "":
			entry.HasError = true
			entry.ErrorMsg = r.Result.Error
		case r.Result != nil:
			for _, finding := range r.Result.Findings {
				rows := []htmlFindingRow{
					{Label: labelRule, Value: finding.Rule},
					{Label: labelCategory, Value: finding.Category},
					{Label: labelDescription, Value: finding.Description},
				}
				if !finding.Success {
					rows = append(rows, htmlFindingRow{Label: labelFix, Value: finding.Remediation})
				}
				entry.Findings = append(entry.Findings, htmlFindingView{
					Title:         finding.Title,
					Rule:          finding.Rule,
					Category:      finding.Category,
					Severity:      finding.Severity,
					SeverityClass: severityClass(finding),
					Success:       finding.Success,
					Rows:          rows,
					HasFixURL:     finding.FixURL != "",
					FixURL:        finding.FixURL,
					VisibleFixURL: displayURL(finding.FixURL),
					HasDocURL:     finding.DocURL != "",
					DocURL:        finding.DocURL,
					VisibleDocURL: displayURL(finding.DocURL),
				})
			}
			entry.Counts = formatSeverityCounts(r.Result)
			entry.Successes = r.Result.CountSuccesses()
		}

		stateCounts[entry.StateClass]++
		entries = append(entries, entry)
	}

	return htmlBatchView{
		ScannedAt:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalRepos:  len(results),
		StateCounts: stateCounts,
		Repos:       entries,
	}
}

// printBatchHTML renders the combined report to outputPath.
func printBatchHTML(results []batchRepoResult, outputPath string) (err error) {
	view := buildBatchView(results)

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file %q: %w", outputPath, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("closing output file %q: %w", outputPath, closeErr)
		}
	}()

	if err := renderHTMLTemplate(f, htmlBatchTemplate, view); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nReport written to %s\n", outputPath)
	return nil
}

// printBatchJSON writes a JSON array of all ScanResults to outputPath.
func printBatchJSON(results []batchRepoResult, outputPath string) (err error) {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file %q: %w", outputPath, err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("closing output file %q: %w", outputPath, closeErr)
		}
	}()

	var scanResults []*scanner.ScanResult
	for _, r := range results {
		if r.Result != nil {
			scanResults = append(scanResults, r.Result)
		} else {
			// Represent hard errors as a minimal ScanResult with Error set
			scanResults = append(scanResults, &scanner.ScanResult{
				RepoFullName: r.RepoFullName,
				RepoURL:      "https://github.com/" + r.RepoFullName,
				Error:        r.Err.Error(),
			})
		}
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(scanResults); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nJSON report written to %s\n", outputPath)
	return nil
}

// htmlBatchCSS extends htmlBaseCSS with sidebar layout styles.
const htmlBatchCSS = `
/* --- batch layout --- */
.page { display: flex; min-height: 100vh; gap: 0; }
.sidebar {
  width: 260px;
  min-width: 220px;
  max-width: 300px;
  flex-shrink: 0;
  background: var(--card-bg);
  border-right: 1px solid var(--card-border);
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  padding: 1rem 0;
  box-sizing: border-box;
}
.sidebar-header { padding: 0 1rem 0.75rem; font-weight: 700; font-size: 0.9rem; color: var(--th-fg); border-bottom: 1px solid var(--row-border); margin-bottom: 0.5rem; }
.sidebar-legend { padding: 0 0 0.5rem; font-size: 0.75rem; color: var(--muted); border-bottom: 1px solid var(--row-border); margin-bottom: 0.5rem; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; padding: 0.3rem 1rem; line-height: 1.2; cursor: pointer; }
.legend-item:hover { background: var(--badge-bg); }
.legend-item.legend-active { background: var(--badge-bg); font-weight: 700; color: var(--fg); }
.legend-count { margin-left: auto; font-variant-numeric: tabular-nums; }
.filter-hidden { display: none !important; }
.sidebar a { display: flex; align-items: center; gap: 0.5rem; padding: 0.35rem 1rem; font-size: 0.82rem; color: var(--th-fg); text-decoration: none; line-height: 1.3; word-break: break-all; }
.sidebar a:hover { background: var(--badge-bg); text-decoration: none; }
.dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.dot-clean         { background: #16a34a; }
.dot-high-findings { background: #dc2626; }
.dot-findings      { background: #d97706; }
.dot-error         { background: #ec4899; }
.main { flex: 1; padding: 2rem; min-width: 0; }
/* repo sections */
.repo-section { margin-bottom: 2.5rem; }
.repo-section h2 { font-size: 1.35rem; margin: 0 0 0.75rem; padding-bottom: 0.4rem; border-bottom: 2px solid var(--row-border); }
.repo-section h2 a { color: inherit; text-decoration: none; }
.repo-section h2 a:hover { text-decoration: underline; }
.repo-error-card { background: var(--badge-bg); border: 1px solid var(--row-border); border-radius: 8px; padding: 0.9rem 1rem; color: var(--muted); font-size: 0.95rem; }
@media (max-width: 768px) {
  .page { flex-direction: column; }
  .sidebar { width: 100%; max-width: 100%; height: auto; position: static; border-right: none; border-bottom: 1px solid var(--card-border); }
  .main { padding: 1rem; }
}
@media print {
  .sidebar { display: none; }
  .main { padding: 0; }
}
`

const htmlBatchTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>GitHub Actions Security Assessment Batch Report</title>
  ` + htmlThemeScript + `
  <style>` + htmlBaseCSS + htmlBatchCSS + `</style>
</head>
<body>
  ` + htmlThemeButton + `
  <div class="page">

    <!-- Sidebar nav -->
    <nav class="sidebar" aria-label="Repository navigation">
      <div class="sidebar-header">{{ .TotalRepos }} repositories</div>
      <div class="sidebar-legend">
        {{- $c := .StateCounts }}
        <div class="legend-item" data-filter="all" tabindex="0"><span>All</span><span class="legend-count">{{ .TotalRepos }}</span></div>
        <div class="legend-item" data-filter="clean" tabindex="0"><span class="dot dot-clean"></span><span>Clean</span><span class="legend-count">{{ index $c "clean" }}</span></div>
        <div class="legend-item" data-filter="findings" tabindex="0"><span class="dot dot-findings"></span><span>Med / low findings</span><span class="legend-count">{{ index $c "findings" }}</span></div>
        <div class="legend-item" data-filter="high-findings" tabindex="0"><span class="dot dot-high-findings"></span><span>High / critical</span><span class="legend-count">{{ index $c "high-findings" }}</span></div>
        <div class="legend-item" data-filter="error" tabindex="0"><span class="dot dot-error"></span><span>Scan error</span><span class="legend-count">{{ index $c "error" }}</span></div>
      </div>
      {{ range .Repos }}
      <a href="#{{ .Anchor }}" data-state="{{ .StateClass }}">
        <span class="dot dot-{{ .StateClass }}"></span>{{ .RepoFullName }}
      </a>
      {{ end }}
    </nav>

    <!-- Main content -->
    <div class="main">
      <div class="wrap">
        <h1>GitHub Actions Security Assessment Batch Report</h1>
        <div class="summary">Scanned {{ .TotalRepos }} repositories &bull; {{ .ScannedAt }}</div>

        <!-- Per-repo sections -->
        {{ range .Repos }}
        <div class="repo-section" id="{{ .Anchor }}" data-state="{{ .StateClass }}">
          <h2><a href="https://github.com/{{ .RepoFullName }}">{{ .RepoFullName }}</a></h2>
          {{ if .HasError }}
          <div class="repo-error-card">Scan error: {{ .ErrorMsg }}</div>
          {{ else }}
          <div class="badges">
            {{ if .Counts }}{{ range .Counts }}<span class="badge">{{ . }}</span>{{ end }}{{ else }}<span class="badge">no findings</span>{{ end }}
            {{ if gt .Successes 0 }}<span class="badge">{{ .Successes }} success{{ if ne .Successes 1 }}es{{ end }}</span>{{ end }}
          </div>
          {{ range .Findings }}
          <section class="card {{ .SeverityClass }}">
            <h2>{{ if .Success }}{{ .Title }}{{ else }}{{ upper .Severity }}  {{ .Title }}{{ end }}</h2>
            <table>
              {{ range .Rows }}<tr><th>{{ .Label }}</th><td>{{ .Value }}</td></tr>{{ end }}
              {{ if .HasFixURL }}<tr><th>Fix URL</th><td><a href="{{ .FixURL }}">{{ .VisibleFixURL }}</a></td></tr>{{ end }}
              {{ if .HasDocURL }}<tr><th>Docs</th><td><a href="{{ .DocURL }}">{{ .VisibleDocURL }}</a></td></tr>{{ end }}
            </table>
          </section>
          {{ end }}
          {{ end }}
        </div>
        {{ end }}

      </div>
    </div>
  </div>
  <script>
  (function(){
    var active = null;
    function applyFilter(f) {
      document.querySelectorAll('.legend-item[data-filter]').forEach(function(el) {
        var key = el.getAttribute('data-filter');
        var on = key === 'all' ? f === null : key === f;
        el.classList.toggle('legend-active', on);
        el.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      document.querySelectorAll('[data-state]').forEach(function(el) {
        el.classList.toggle('filter-hidden', f !== null && el.getAttribute('data-state') !== f);
      });
    }
    document.querySelectorAll('.legend-item[data-filter]').forEach(function(item) {
      item.setAttribute('role', 'button');
      item.setAttribute('aria-pressed', 'false');
      item.addEventListener('click', function() {
        var f = this.getAttribute('data-filter');
        active = (f === 'all' || active === f) ? null : f;
        applyFilter(active);
      });
      item.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.click(); }
      });
    });
    applyFilter(active);
  })();
  </script>
</body>
</html>
`
