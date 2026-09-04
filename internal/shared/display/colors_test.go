package display

import "testing"

func TestColorFunc(t *testing.T) {
	wrap := ColorFunc(Red)
	got := wrap("danger")
	want := Red + "danger" + Reset
	if got != want {
		t.Errorf("ColorFunc(Red)(danger) = %q, want %q", got, want)
	}
}

func TestColorize(t *testing.T) {
	got := Colorize("hello", Blue)
	want := Blue + "hello" + Reset
	if got != want {
		t.Errorf("Colorize(hello, Blue) = %q, want %q", got, want)
	}
}

func TestColorHelpers(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) string
		want string
	}{
		{"RedText", RedText, BoldRed + "x" + Reset},
		{"GreenText", GreenText, BoldGreen + "x" + Reset},
		{"YellowText", YellowText, BoldYellow + "x" + Reset},
		{"BlueText", BlueText, BoldBlue + "x" + Reset},
		{"MagentaText", MagentaText, BoldMagenta + "x" + Reset},
		{"CyanText", CyanText, BoldCyan + "x" + Reset},
		{"WhiteText", WhiteText, BoldWhite + "x" + Reset},
		{"DimText", DimText, Dim + "x" + Reset},
	}

	for _, tt := range tests {
		if got := tt.fn("x"); got != tt.want {
			t.Errorf("%s(x) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", BoldMagenta},
		{"HIGH", BoldRed},
		{"MEDIUM", BoldYellow},
		{"LOW", BoldCyan},
		{"INFO", BoldBlue},
		{"WHATEVER", Reset},
	}

	for _, tt := range tests {
		if got := SeverityColor(tt.severity); got != tt.want {
			t.Errorf("SeverityColor(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestColorSeverity(t *testing.T) {
	got := ColorSeverity("HIGH")
	want := BoldRed + "HIGH" + Reset
	if got != want {
		t.Errorf("ColorSeverity(HIGH) = %q, want %q", got, want)
	}
}

func TestIcons(t *testing.T) {
	tests := []struct {
		name string
		fn   func() string
		want string
	}{
		{"SuccessIcon", SuccessIcon, GreenText("[+]")},
		{"ErrorIcon", ErrorIcon, RedText("[-]")},
		{"InfoIcon", InfoIcon, BlueText("[*]")},
		{"WarningIcon", WarningIcon, YellowText("[!]")},
	}

	for _, tt := range tests {
		if got := tt.fn(); got != tt.want {
			t.Errorf("%s() = %q, want %q", tt.name, got, tt.want)
		}
	}
}
