package catalog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCatalogIsValidAndDeterministic(t *testing.T) {
	t.Parallel()

	items := All()
	if err := Validate(items); err != nil {
		t.Fatalf("Validate(All()) error = %v", err)
	}
	for index := 1; index < len(items); index++ {
		if items[index-1].Path >= items[index].Path {
			t.Fatalf("catalog is not strictly sorted: %q then %q", items[index-1].Path, items[index].Path)
		}
	}
}

func TestValidateRejectsUnsafeTUICommand(t *testing.T) {
	t.Parallel()

	for _, safety := range []SafetyLevel{SafetyActive, SafetyDangerous} {
		t.Run(string(safety), func(t *testing.T) {
			t.Parallel()
			err := Validate([]Entry{{
				Path:       "raxuiscli attack",
				Summary:    "Attack a target",
				Category:   "offensive",
				Maturity:   MaturityExperimental,
				Safety:     safety,
				TUIAllowed: true,
			}})
			if err == nil {
				t.Fatalf("Validate() accepted a %s TUI command", safety)
			}
		})
	}
}

func TestAllReturnsCopy(t *testing.T) {
	t.Parallel()

	first := All()
	if len(first) == 0 {
		t.Skip("catalog population is covered by the Cobra parity test")
	}
	first[0].Path = "mutated"
	if second := All(); second[0].Path == "mutated" {
		t.Fatal("All() exposed mutable catalog storage")
	}
}

func TestCatalogUsesEveryMaturityAndSafetyLevel(t *testing.T) {
	t.Parallel()

	maturities := map[Maturity]bool{}
	safetyLevels := map[SafetyLevel]bool{}
	for _, entry := range All() {
		maturities[entry.Maturity] = true
		safetyLevels[entry.Safety] = true
	}
	for _, maturity := range []Maturity{MaturityStable, MaturityExperimental, MaturityInformational} {
		if !maturities[maturity] {
			t.Errorf("catalog has no %q maturity entry", maturity)
		}
	}
	for _, safety := range []SafetyLevel{SafetySafe, SafetyPassive, SafetyActive, SafetyDangerous} {
		if !safetyLevels[safety] {
			t.Errorf("catalog has no %q safety entry", safety)
		}
	}
}

func TestOnlyApprovedFlowsAreTUIAllowed(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"raxuiscli audit web": true,
		"raxuiscli compare":   true,
		"raxuiscli demo web":  true,
	}
	for _, entry := range All() {
		if entry.TUIAllowed != want[entry.Path] {
			t.Errorf("%s TUIAllowed = %v, want %v", entry.Path, entry.TUIAllowed, want[entry.Path])
		}
	}
}

func TestGeneratedStatusRenderingIsDeterministic(t *testing.T) {
	t.Parallel()

	items := []Entry{
		{Path: "raxuiscli z", Summary: "Last", Category: "tools", Maturity: MaturityExperimental, Safety: SafetyActive},
		{Path: "raxuiscli a", Summary: "First", Category: "audit & reporting", Maturity: MaturityStable, Safety: SafetyPassive, TUIAllowed: true},
	}
	readme, err := RenderReadmeStatus(items)
	if err != nil {
		t.Fatalf("RenderReadmeStatus() error = %v", err)
	}
	if !strings.Contains(readme, "| audit & reporting | 1 | 0 | 0 | 1 |") || !strings.Contains(readme, "| tools | 0 | 1 | 0 | 1 |") {
		t.Fatalf("RenderReadmeStatus() = %q", readme)
	}
	roadmap, err := RenderRoadmapStatus(items)
	if err != nil {
		t.Fatalf("RenderRoadmapStatus() error = %v", err)
	}
	if strings.Index(roadmap, "`raxuiscli a`") > strings.Index(roadmap, "`raxuiscli z`") {
		t.Fatalf("RenderRoadmapStatus() is not path sorted:\n%s", roadmap)
	}
}

func TestReplaceGeneratedBlockPreservesSurroundingContent(t *testing.T) {
	t.Parallel()

	document := "before\n" + BeginMarker + "\nstale\n" + EndMarker + "\nafter\n"
	got, err := ReplaceGeneratedBlock(document, "fresh\ncontent")
	if err != nil {
		t.Fatalf("ReplaceGeneratedBlock() error = %v", err)
	}
	want := "before\n" + BeginMarker + "\nfresh\ncontent\n" + EndMarker + "\nafter\n"
	if got != want {
		t.Fatalf("ReplaceGeneratedBlock() = %q, want %q", got, want)
	}
}

func TestReplaceGeneratedBlockRejectsInvalidMarkers(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing":     "plain document",
		"duplicate":   BeginMarker + BeginMarker + EndMarker,
		"reversed":    EndMarker + BeginMarker,
		"missing end": BeginMarker,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ReplaceGeneratedBlock(document, "new"); err == nil {
				t.Fatal("ReplaceGeneratedBlock() accepted invalid markers")
			}
		})
	}
}

func TestValidateRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	base := Entry{Path: "raxuiscli example", Summary: "Example", Category: "test", Maturity: MaturityStable, Safety: SafetySafe}
	tests := map[string][]Entry{
		"duplicate":        {base, base},
		"empty path":       {{Summary: base.Summary, Category: base.Category, Maturity: base.Maturity, Safety: base.Safety}},
		"empty summary":    {{Path: base.Path, Category: base.Category, Maturity: base.Maturity, Safety: base.Safety}},
		"empty category":   {{Path: base.Path, Summary: base.Summary, Maturity: base.Maturity, Safety: base.Safety}},
		"invalid maturity": {{Path: base.Path, Summary: base.Summary, Category: base.Category, Maturity: "unknown", Safety: base.Safety}},
		"invalid safety":   {{Path: base.Path, Summary: base.Summary, Category: base.Category, Maturity: base.Maturity, Safety: "unknown"}},
	}
	for name, items := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(items); err == nil {
				t.Fatal("Validate() accepted invalid metadata")
			}
		})
	}
}

func TestGeneratedDocumentationIsCurrent(t *testing.T) {
	t.Parallel()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() could not locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	generated := map[string]func([]Entry) (string, error){
		"README.md":  RenderReadmeStatus,
		"ROADMAP.md": RenderRoadmapStatus,
	}
	for name, render := range generated {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(root, name)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", path, err)
			}
			section, err := render(All())
			if err != nil {
				t.Fatalf("render status error = %v", err)
			}
			after, err := ReplaceGeneratedBlock(string(before), section)
			if err != nil {
				t.Fatalf("ReplaceGeneratedBlock(%s) error = %v", name, err)
			}
			if after != string(before) {
				t.Fatalf("%s is stale; run go generate ./internal/shared/catalog/...", name)
			}
		})
	}
}
