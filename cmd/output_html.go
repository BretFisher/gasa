package cmd

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/bretfisher/gasa/internal/scanner"
)

type htmlFindingRow struct {
	Label string
	Value template.HTML
}

// markdownCodeToHTML converts the small subset of Markdown our rule copy uses —
// inline `code` spans and ```fenced``` blocks — into <code>/<pre><code> HTML,
// HTML-escaping every other character (and the code content itself). It is
// deliberately not a full Markdown parser: rule messages only ever use these two
// constructs, so a tiny hand-rolled converter is safer and dependency-free.
// Returning template.HTML tells html/template the result is already escaped.
func markdownCodeToHTML(s string) template.HTML {
	var b strings.Builder
	for len(s) > 0 {
		switch {
		case strings.HasPrefix(s, "```"):
			// Drop an optional language token on the opening fence line, then take
			// everything up to the closing fence.
			_, rest, _ := strings.Cut(s[3:], "\n")
			code, after, _ := strings.Cut(rest, "```")
			b.WriteString("<pre><code>")
			b.WriteString(template.HTMLEscapeString(strings.Trim(code, "\n")))
			b.WriteString("</code></pre>")
			s = after
		case strings.HasPrefix(s, "`"):
			if code, after, found := strings.Cut(s[1:], "`"); found {
				b.WriteString("<code>")
				b.WriteString(template.HTMLEscapeString(code))
				b.WriteString("</code>")
				s = after
			} else {
				b.WriteString("`") // unmatched backtick: emit literally
				s = s[1:]
			}
		default:
			// Emit text up to the next backtick, HTML-escaped.
			if before, after, found := strings.Cut(s, "`"); found {
				b.WriteString(template.HTMLEscapeString(before))
				s = "`" + after
			} else {
				b.WriteString(template.HTMLEscapeString(s))
				s = ""
			}
		}
	}
	// Safe despite G203: every dynamic segment — surrounding text AND the code
	// content — is run through template.HTMLEscapeString above; the only literal
	// HTML written is our own fixed <code>/<pre> tags. No attacker-controlled
	// input reaches the output unescaped, so this is not an XSS sink.
	return template.HTML(b.String()) //nolint:gosec // G203: all dynamic content is escaped above; only fixed tags are injected
}

type htmlFindingView struct {
	Title         string
	Rule          string
	Category      string
	Severity      string
	SeverityClass string
	Success       bool
	Rows          []htmlFindingRow
	VisibleFixURL string
	HasFixURL     bool
	VisibleDocURL string
	HasDocURL     bool
	FixURL        string
	DocURL        string
}

type htmlResultView struct {
	RepoFullName string
	Counts       []string
	Successes    int
	Incomplete   []string
	Findings     []htmlFindingView
}

type htmlRuleView struct {
	Title         string
	Rule          string
	Category      string
	Description   template.HTML
	Severity      string
	SeverityClass string
	Aliases       string
	HasDocURL     bool
	DocURL        string
	VisibleDocURL string
}

func printHTML(result *scanner.ScanResult) error {
	view := htmlResultView{
		RepoFullName: result.RepoFullName,
		Counts:       formatSeverityCounts(result),
		Successes:    result.CountSuccesses(),
		Incomplete:   result.Incomplete,
		Findings:     make([]htmlFindingView, 0, len(result.Findings)),
	}

	for _, finding := range result.Findings {
		rows := []htmlFindingRow{
			{Label: labelRule, Value: markdownCodeToHTML(finding.Rule)},
			{Label: labelCategory, Value: markdownCodeToHTML(finding.Category)},
			{Label: labelDescription, Value: markdownCodeToHTML(finding.Description)},
		}
		if !finding.Success {
			rows = append(rows, htmlFindingRow{Label: labelFix, Value: markdownCodeToHTML(finding.Remediation)})
		}

		view.Findings = append(view.Findings, htmlFindingView{
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

	return renderHTMLTemplate(os.Stdout, htmlResultTemplate, view)
}

func printRulesHTML() error {
	rules := scanner.AvailableRules()
	views := make([]htmlRuleView, 0, len(rules))
	for _, rule := range rules {
		aliases := ""
		if len(rule.Aliases) > 0 {
			aliases = strings.Join(rule.Aliases, ", ")
		}
		views = append(views, htmlRuleView{
			Title:         rule.Title,
			Rule:          rule.Name,
			Category:      rule.Category,
			Description:   markdownCodeToHTML(rule.Description),
			Severity:      rule.Severity,
			SeverityClass: severityClass(scanner.Finding{Severity: rule.Severity}),
			Aliases:       aliases,
			HasDocURL:     rule.DocURL() != "",
			DocURL:        rule.DocURL(),
			VisibleDocURL: displayURL(rule.DocURL()),
		})
	}
	return renderHTMLTemplate(os.Stdout, htmlRulesTemplate, views)
}

func renderHTMLTemplate(out io.Writer, text string, data any) error {
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(text)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}
	if err := tmpl.Execute(out, data); err != nil {
		return fmt.Errorf("rendering HTML: %w", err)
	}
	return nil
}

func severityClass(f scanner.Finding) string {
	if f.Success {
		return "success"
	}
	switch f.Severity {
	case scanner.SeverityCritical:
		return scanner.SeverityCritical
	case scanner.SeverityHigh:
		return scanner.SeverityHigh
	case scanner.SeverityMedium:
		return scanner.SeverityMedium
	case scanner.SeverityLow:
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}

func formatSeverityCounts(result *scanner.ScanResult) []string {
	counts := result.CountBySeverity()
	parts := []string{}
	for _, severity := range []string{scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo} {
		if c := counts[severity]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, severity))
		}
	}
	return parts
}

func displayURL(raw string) string {
	if raw == "" {
		return ""
	}
	// Rule doc links are blob URLs into this repo; show just the repo-relative
	// path (e.g. "docs/rules/pull-request-target.md") instead of the full URL.
	if idx := strings.Index(raw, "/docs/rules/"); idx != -1 {
		return raw[idx+1:]
	}
	if trimmed, ok := strings.CutPrefix(raw, "https://github.com/"); ok {
		return trimmed
	}
	return raw
}

const htmlBaseCSS = `
:root {
  color-scheme: light dark;
  --bg: #f6f8fb;
  --fg: #16181d;
  --muted: #4b5563;
  --card-bg: #fff;
  --card-border: #d0d7de;
  --card-shadow: 0 1px 2px rgba(0,0,0,0.04);
  --badge-bg: #e5e7eb;
  --row-border: #e5e7eb;
  --th-fg: #374151;
  --link: #0969da;
  --sev-critical-bg: #b42318; --sev-critical-fg: #fff;
  --sev-high-bg: #fff1f2;     --sev-high-fg: #b42318;
  --sev-medium-bg: #fff8c5;   --sev-medium-fg: #9a6700;
  --sev-low-bg: #ecfeff;      --sev-low-fg: #0c5460;
  --sev-info-bg: #f3f4f6;     --sev-info-fg: #667085;
  --sev-success-bg: #ecfdf3;  --sev-success-fg: #166534;
}
:root[data-theme="dark"] {
  --bg: #0d1117;
  --fg: #e6edf3;
  --muted: #9ca3af;
  --card-bg: #161b22;
  --card-border: #30363d;
  --card-shadow: 0 1px 2px rgba(0,0,0,0.4);
  --badge-bg: #21262d;
  --row-border: #21262d;
  --th-fg: #c9d1d9;
  --link: #58a6ff;
  --sev-critical-bg: #7f1d1d; --sev-critical-fg: #fee2e2;
  --sev-high-bg: #3b1418;     --sev-high-fg: #fca5a5;
  --sev-medium-bg: #3a2e08;   --sev-medium-fg: #fde68a;
  --sev-low-bg: #052e2e;      --sev-low-fg: #a5f3fc;
  --sev-info-bg: #1f2937;     --sev-info-fg: #9ca3af;
  --sev-success-bg: #052e16;  --sev-success-fg: #86efac;
}
/* No-JS fallback: if data-theme is never set, follow the system. */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme]) {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #9ca3af;
    --card-bg: #161b22;
    --card-border: #30363d;
    --card-shadow: 0 1px 2px rgba(0,0,0,0.4);
    --badge-bg: #21262d;
    --row-border: #21262d;
    --th-fg: #c9d1d9;
    --link: #58a6ff;
    --sev-critical-bg: #7f1d1d; --sev-critical-fg: #fee2e2;
    --sev-high-bg: #3b1418;     --sev-high-fg: #fca5a5;
    --sev-medium-bg: #3a2e08;   --sev-medium-fg: #fde68a;
    --sev-low-bg: #052e2e;      --sev-low-fg: #a5f3fc;
    --sev-info-bg: #1f2937;     --sev-info-fg: #9ca3af;
    --sev-success-bg: #052e16;  --sev-success-fg: #86efac;
  }
}
.theme-toggle {
  position: fixed; top: 1rem; right: 1rem; z-index: 100;
  background: var(--card-bg); color: var(--fg);
  border: 1px solid var(--card-border); border-radius: 999px;
  padding: 0.4rem 0.85rem; font-size: 0.85rem; font-family: inherit;
  cursor: pointer; box-shadow: var(--card-shadow);
}
.theme-toggle:hover { background: var(--badge-bg); }
@media print { .theme-toggle { display: none; } }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); margin: 0; padding: 2rem; }
.wrap { max-width: 1100px; margin: 0 auto; }
h1 { margin: 0 0 0.5rem; font-size: 1.9rem; }
.summary { margin: 0 0 1.5rem; color: var(--muted); font-size: 0.98rem; }
.badges { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.75rem 0 1.75rem; }
.badge { background: var(--badge-bg); border-radius: 999px; padding: 0.3rem 0.7rem; font-size: 0.9rem; }
.card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; margin: 0 0 1rem; box-shadow: var(--card-shadow); overflow: hidden; }
.card h2 { margin: 0; padding: 0.9rem 1rem; font-size: 1.05rem; font-weight: 700; }
.critical h2 { color: var(--sev-critical-fg); background: var(--sev-critical-bg); }
.high h2     { color: var(--sev-high-fg);     background: var(--sev-high-bg); }
.medium h2   { color: var(--sev-medium-fg);   background: var(--sev-medium-bg); }
.low h2      { color: var(--sev-low-fg);      background: var(--sev-low-bg); }
.info h2     { color: var(--sev-info-fg);     background: var(--sev-info-bg); }
.success h2  { color: var(--sev-success-fg);  background: var(--sev-success-bg); }
.incomplete h2 { color: var(--sev-medium-fg); background: var(--sev-medium-bg); }
.incomplete ul { margin: 0; padding: 0.8rem 1rem 0.8rem 2.2rem; }
.incomplete li { padding: 0.15rem 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 0.8rem 1rem; border-top: 1px solid var(--row-border); }
th { width: 10rem; font-weight: 700; color: var(--th-fg); }
td { white-space: pre-wrap; word-break: break-word; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 0.88em; background: var(--badge-bg); padding: 0.12em 0.34em; border-radius: 6px; }
pre { background: var(--badge-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 0.85rem 1rem; margin: 0.5rem 0; overflow-x: auto; }
pre code { background: none; padding: 0; font-size: 0.85em; line-height: 1.45; }
@media print { body { background: #fff; color: #16181d; padding: 0; } .card { box-shadow: none; break-inside: avoid; } }
`

// htmlThemeScript resolves the theme before paint and wires up the toggle.
// Runs synchronously in <head> so data-theme is set on <html> before <body> renders.
const htmlThemeScript = `<script>
(function(){
  var KEY = 'gasa-theme';
  var mq = window.matchMedia('(prefers-color-scheme: dark)');
  function resolved(pref){
    if (pref === 'light' || pref === 'dark') return pref;
    return mq.matches ? 'dark' : 'light';
  }
  function apply(pref){
    document.documentElement.setAttribute('data-theme', resolved(pref));
    var btn = document.querySelector('[data-theme-toggle]');
    if (btn) btn.textContent = 'Theme: ' + (pref || 'auto');
  }
  apply(localStorage.getItem(KEY));
  mq.addEventListener('change', function(){
    var p = localStorage.getItem(KEY);
    if (!p) apply(null);
  });
  document.addEventListener('DOMContentLoaded', function(){
    apply(localStorage.getItem(KEY));
    var btn = document.querySelector('[data-theme-toggle]');
    if (!btn) return;
    btn.addEventListener('click', function(){
      var cur = localStorage.getItem(KEY) || 'auto';
      var next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
      if (next === 'auto') localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, next);
      apply(next === 'auto' ? null : next);
    });
  });
})();
</script>`

const htmlThemeButton = `<button type="button" class="theme-toggle" data-theme-toggle aria-label="Toggle theme">Theme: auto</button>`

// htmlIncompleteCard renders the partial-scan warning. It expects the current
// template dot to expose an .Incomplete []string and is shared by the single
// and batch report templates.
const htmlIncompleteCard = `{{ if .Incomplete }}
    <section class="card incomplete">
      <h2>&#9888; {{ len .Incomplete }} check(s) could not be completed &mdash; findings may be partial</h2>
      <ul>{{ range .Incomplete }}<li>{{ . }}</li>{{ end }}</ul>
    </section>
    {{ end }}`

const htmlResultTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{{ .RepoFullName }} - gasa report</title>
  ` + htmlThemeScript + `
  <style>` + htmlBaseCSS + `</style>
</head>
<body>
  ` + htmlThemeButton + `
  <div class="wrap">
    <h1>{{ .RepoFullName }}</h1>
    <div class="summary">GitHub Actions Security Assessment report</div>
    <div class="badges">
      {{ if .Counts }}{{ range .Counts }}<span class="badge">{{ . }}</span>{{ end }}{{ else }}<span class="badge">no findings</span>{{ end }}
      {{ if gt .Successes 0 }}<span class="badge">{{ .Successes }} success{{ if ne .Successes 1 }}es{{ end }}</span>{{ end }}
    </div>
    ` + htmlIncompleteCard + `
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
  </div>
</body>
</html>
`

const htmlRulesTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>gasa rules</title>
  ` + htmlThemeScript + `
  <style>` + htmlBaseCSS + `</style>
</head>
<body>
  ` + htmlThemeButton + `
  <div class="wrap">
    <h1>Available Rules</h1>
    <div class="summary">Canonical rule names and aliases</div>
    {{ range . }}
    <section class="card {{ .SeverityClass }}">
      <h2>{{ upper .Severity }}  {{ .Title }}</h2>
      <table>
        <tr><th>Rule</th><td>{{ .Rule }}</td></tr>
        <tr><th>Category</th><td>{{ .Category }}</td></tr>
        <tr><th>Description</th><td>{{ .Description }}</td></tr>
        {{ if .Aliases }}<tr><th>Aliases</th><td>{{ .Aliases }}</td></tr>{{ end }}
        {{ if .HasDocURL }}<tr><th>Docs</th><td><a href="{{ .DocURL }}">{{ .VisibleDocURL }}</a></td></tr>{{ end }}
      </table>
    </section>
    {{ end }}
  </div>
</body>
</html>
`
