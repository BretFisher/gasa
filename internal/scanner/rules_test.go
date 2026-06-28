package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAvailableRules_Count(t *testing.T) {
	rules := AvailableRules()
	if got := len(rules); got != 10 {
		t.Errorf("AvailableRules() returned %d rules, want 10", got)
	}
}

// TestRuleDocsCoverage guards the rule <-> docs/rules/*.md binding that is now
// the single source of truth for rule metadata and report copy. It catches the
// failure modes the front-matter design introduces: a rule with firing logic
// but no doc page (or vice versa), a doc missing required fields, and a doc
// whose page link would 404.
func TestRuleDocsCoverage(t *testing.T) {
	docsDir := filepath.Join("..", "..", "docs", "rules")

	// Every rule with firing logic must have a loaded doc.
	for name := range runFuncs {
		if _, ok := ruleDocRegistry[name]; !ok {
			t.Errorf("runFuncs has %q but no docs/rules page declares it", name)
		}
	}
	// Every loaded doc must have firing logic, required fields, and a real file.
	for name, doc := range ruleDocRegistry {
		if _, ok := runFuncs[name]; !ok {
			t.Errorf("docs/rules declares rule %q but no runFunc is registered", name)
		}
		if doc.Title == "" || doc.Category == "" || doc.Severity == "" || doc.Description == "" {
			t.Errorf("rule %q is missing required front-matter (title/category/severity/description)", name)
		}
		if !isValidSeverity(doc.Severity) {
			t.Errorf("rule %q has invalid severity %q", name, doc.Severity)
		}
		hasPass := false
		for key := range doc.Messages {
			if key == "pass" || strings.HasPrefix(key, "pass-") {
				hasPass = true
				break
			}
		}
		if !hasPass {
			t.Errorf("rule %q has no pass/pass-* message", name)
		}
		if _, err := os.Stat(filepath.Join(docsDir, doc.DocFile+".md")); err != nil {
			t.Errorf("rule %q DocFile %q: %v", name, doc.DocFile, err)
		}
	}
}

func TestAvailableRules_UniqueNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, rule := range AvailableRules() {
		if seen[rule.Name] {
			t.Errorf("duplicate rule name: %s", rule.Name)
		}
		seen[rule.Name] = true
	}
}

func TestResolveRuleNames_Empty(t *testing.T) {
	rules, err := ResolveRuleNames(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != len(AvailableRules()) {
		t.Errorf("got %d rules, want %d", len(rules), len(AvailableRules()))
	}
}

func TestResolveRuleNames_ByCanonical(t *testing.T) {
	for _, rule := range AvailableRules() {
		resolved, err := ResolveRuleNames([]string{rule.Name})
		if err != nil {
			t.Fatalf("unexpected error resolving %s: %v", rule.Name, err)
		}
		if len(resolved) != 1 || resolved[0].Name != rule.Name {
			t.Fatalf("resolved = %+v, want %s", resolved, rule.Name)
		}
	}
}

func TestResolveRuleNames_ByAlias(t *testing.T) {
	for _, rule := range AvailableRules() {
		for _, alias := range rule.Aliases {
			resolved, err := ResolveRuleNames([]string{alias})
			if err != nil {
				t.Fatalf("unexpected error resolving alias %s: %v", alias, err)
			}
			if len(resolved) != 1 || resolved[0].Name != rule.Name {
				t.Fatalf("alias %s resolved = %+v, want %s", alias, resolved, rule.Name)
			}
		}
	}
}

func TestResolveRuleNames_Unknown(t *testing.T) {
	_, err := ResolveRuleNames([]string{"not-a-real-rule"})
	if err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestResolveRuleNames_Dedup(t *testing.T) {
	resolved, err := ResolveRuleNames([]string{"workflows/action-version-pinning", "action-pinning"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolved %d rules, want 1", len(resolved))
	}
	if resolved[0].Name != "workflows/action-version-pinning" {
		t.Fatalf("resolved rule = %s", resolved[0].Name)
	}
}

func TestResolveRules_BySeverity(t *testing.T) {
	resolved, err := resolveRules(nil, nil, []string{SeverityCritical, SeverityMedium}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, rule := range resolved {
		if rule.Severity != SeverityCritical && rule.Severity != SeverityMedium {
			t.Fatalf("resolved rule %s has severity %s", rule.Name, rule.Severity)
		}
	}

	if len(resolved) != 5 {
		t.Fatalf("resolved %d rules, want 5", len(resolved))
	}
}

func TestResolveRules_BySeverityUsesConfigOverride(t *testing.T) {
	resolved, err := resolveRules(nil, nil, []string{SeverityCritical}, &Config{
		Overrides: []RuleOverride{{Rule: "workflows/action-version-pinning", Severity: SeverityCritical}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seen := make(map[string]bool, len(resolved))
	for _, rule := range resolved {
		seen[rule.Name] = true
	}
	if !seen["workflows/pull-request-target"] {
		t.Fatalf("missing built-in critical rule")
	}
	if !seen["workflows/action-version-pinning"] {
		t.Fatalf("missing severity-overridden rule")
	}
}

func TestResolveRules_InvalidSeverity(t *testing.T) {
	_, err := resolveRules(nil, nil, []string{"urgent"}, nil)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}
