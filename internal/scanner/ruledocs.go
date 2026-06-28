package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// This file makes docs/rules/*.md the single source of truth for rule metadata
// and all human-facing report copy. Each markdown file carries YAML front-matter
// (machine fields + a `messages` map of report templates); the prose body below
// stays the deep human documentation. The Go code keeps only the firing logic
// (runFuncs) and renders copy from the loaded registry.

// messageTemplate is one report message (one finding shape) for a rule. Each
// field is a Go text/template rendered against per-finding data, so dynamic
// values (action names, file paths, errors) stay out of the markdown.
type messageTemplate struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Fix         string `yaml:"fix"`
}

// ruleDoc is the parsed front-matter of one docs/rules/*.md file.
type ruleDoc struct {
	Name        string                     `yaml:"name"`
	Order       int                        `yaml:"order"`
	Title       string                     `yaml:"title"`
	Category    string                     `yaml:"category"`
	Severity    string                     `yaml:"severity"`
	Aliases     []string                   `yaml:"aliases"`
	Description string                     `yaml:"description"`
	Messages    map[string]messageTemplate `yaml:"messages"`

	// DocFile is the slug (filename without .md); derived from the filename, not
	// the front-matter, so the two can never disagree.
	DocFile string `yaml:"-"`
}

// ruleDocRegistry holds the loaded rule documentation. It is populated once at
// startup by LoadRuleDocs and read by the rest of the scanner. Treated as
// immutable after load.
var ruleDocRegistry = map[string]ruleDoc{}

// LoadRuleDocs parses every *.md file in fsys (a directory of rule pages) and
// populates the registry. Production passes the embedded docs/rules FS; tests
// pass os.DirFS pointed at the real files. It is safe to call more than once
// (the last call wins), which keeps test setup simple.
func LoadRuleDocs(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("reading rule docs: %w", err)
	}

	loaded := make(map[string]ruleDoc)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".md") {
			continue
		}
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		doc, err := parseRuleDoc(raw)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", name, err)
		}
		if doc.Name == "" {
			// A page with no front-matter `name` is documentation-only; skip it.
			continue
		}
		doc.DocFile = strings.TrimSuffix(path.Base(name), ".md")
		if existing, dup := loaded[doc.Name]; dup {
			return fmt.Errorf("duplicate rule name %q in %s and %s.md", doc.Name, name, existing.DocFile)
		}
		loaded[doc.Name] = doc
	}

	ruleDocRegistry = loaded
	return nil
}

// frontMatterDelim separates YAML front-matter from the markdown body.
const frontMatterDelim = "---"

// parseRuleDoc extracts and unmarshals the leading YAML front-matter block. A
// file without a leading `---` fence yields an empty doc (no error) so plain
// docs pages are ignored rather than rejected.
func parseRuleDoc(raw []byte) (ruleDoc, error) {
	content := bytes.TrimPrefix(raw, []byte("\uFEFF"))
	content = bytes.TrimLeft(content, " \t\r\n")
	if !bytes.HasPrefix(content, []byte(frontMatterDelim+"\n")) &&
		!bytes.HasPrefix(content, []byte(frontMatterDelim+"\r\n")) {
		return ruleDoc{}, nil
	}
	// Drop the opening fence line, then split on the closing fence.
	rest := content[len(frontMatterDelim):]
	rest = bytes.TrimLeft(rest, "\r\n")
	end := bytes.Index(rest, []byte("\n"+frontMatterDelim))
	if end == -1 {
		return ruleDoc{}, fmt.Errorf("front-matter opening %q has no closing %q", frontMatterDelim, frontMatterDelim)
	}
	var doc ruleDoc
	if err := yaml.Unmarshal(rest[:end], &doc); err != nil {
		return ruleDoc{}, fmt.Errorf("invalid front-matter YAML: %w", err)
	}
	return doc, nil
}

// loadedRuleDocs returns the registry entries sorted by their front-matter
// `order` field (falling back to name), giving the curated category grouping
// regardless of filesystem read order.
func loadedRuleDocs() []ruleDoc {
	docs := make([]ruleDoc, 0, len(ruleDocRegistry))
	for _, d := range ruleDocRegistry {
		docs = append(docs, d)
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Order != docs[j].Order {
			return docs[i].Order < docs[j].Order
		}
		return docs[i].Name < docs[j].Name
	})
	return docs
}

// renderedMessage is a fully-rendered report message for a single finding.
type renderedMessage struct {
	Title       string
	Description string
	Fix         string
}

// renderRuleMessage looks up message `key` for `ruleName` and renders each
// template field against `data`. It returns an error (rather than silently
// emitting blanks) so a missing key or bad placeholder is caught by tests.
func renderRuleMessage(ruleName, key string, data any) (renderedMessage, error) {
	doc, ok := ruleDocRegistry[ruleName]
	if !ok {
		return renderedMessage{}, fmt.Errorf("no rule doc loaded for %q (did LoadRuleDocs run?)", ruleName)
	}
	msg, ok := doc.Messages[key]
	if !ok {
		return renderedMessage{}, fmt.Errorf("rule %q has no message %q", ruleName, key)
	}
	title, err := renderTemplate(ruleName, key, "title", msg.Title, data)
	if err != nil {
		return renderedMessage{}, err
	}
	desc, err := renderTemplate(ruleName, key, "description", msg.Description, data)
	if err != nil {
		return renderedMessage{}, err
	}
	fix, err := renderTemplate(ruleName, key, "fix", msg.Fix, data)
	if err != nil {
		return renderedMessage{}, err
	}
	return renderedMessage{Title: title, Description: desc, Fix: fix}, nil
}

// ruleMessage is the non-erroring wrapper the rule evaluators use. A missing
// key or bad placeholder is a programming/config bug that TestRuleDocsCoverage
// is meant to catch, so rather than panic in production it surfaces the error in
// the finding text — visible and debuggable, never a crash mid-scan.
func ruleMessage(ruleName, key string, data any) renderedMessage {
	msg, err := renderRuleMessage(ruleName, key, data)
	if err != nil {
		return renderedMessage{Title: "rule message error", Description: err.Error()}
	}
	return msg
}

func renderTemplate(ruleName, key, field, text string, data any) (string, error) {
	if !strings.Contains(text, "{{") {
		return text, nil // no placeholders, skip the template engine
	}
	tmpl, err := template.New(field).Option("missingkey=error").Parse(text)
	if err != nil {
		return "", fmt.Errorf("rule %q message %q %s: %w", ruleName, key, field, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rule %q message %q %s: %w", ruleName, key, field, err)
	}
	return buf.String(), nil
}
