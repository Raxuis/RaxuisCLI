package report

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedactURLRemovesCredentialsAndQueryValues(t *testing.T) {
	got := RedactURL("https://alice:password@example.com:8443/private?token=abc123&search=needle#fragment")
	want := "https://example.com:8443/private?search=<redacted>&token=<redacted>"
	if got != want {
		t.Errorf("RedactURL() = %q, want %q", got, want)
	}
}

func TestRedactHeadersRemovesCookieAndAuthorizationValues(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer bearer-secret"},
		"Cookie":        {"session=cookie-secret; theme=dark"},
		"X-Request-Id":  {"safe"},
	}

	got := RedactHeaders(headers)
	if got.Get("Authorization") != RedactedValue || got.Get("Cookie") != RedactedValue {
		t.Errorf("sensitive headers = %#v, want redacted values", got)
	}
	if got.Get("X-Request-ID") != "safe" {
		t.Errorf("safe header = %q, want preserved", got.Get("X-Request-ID"))
	}
	if headers.Get("Authorization") != "Bearer bearer-secret" {
		t.Error("RedactHeaders must not mutate its input")
	}
}

func TestRedactStringRemovesSecretsEmbeddedInErrors(t *testing.T) {
	errText := "request failed for https://bob:url-secret@example.com/a?api_key=query-secret: Authorization: Bearer bearer-secret; Cookie: session=cookie-secret; password=inline-secret"
	got := RedactString(errText)

	for _, secret := range []string{"url-secret", "query-secret", "bearer-secret", "cookie-secret", "inline-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("RedactString exposed %q in %q", secret, got)
		}
	}
}
