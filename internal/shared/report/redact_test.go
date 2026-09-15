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

func TestRedactStringRemovesExtendedSecretKeysAndFTPURLCredentials(t *testing.T) {
	errText := "upload failed for ftp://alice:ftp-secret@example.com/report client_secret=client-value; client-secret: dashed-secret; client.secret = dotted-secret; client secret: spaced-secret; credential=credential-secret"
	got := RedactString(errText)

	for _, secret := range []string{"ftp-secret", "client-value", "dashed-secret", "dotted-secret", "spaced-secret", "credential-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("RedactString exposed %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "ftp://example.com/report") {
		t.Errorf("RedactString() = %q, want redacted FTP URL preserved", got)
	}
}

func TestRedactStringPreservesOrdinaryText(t *testing.T) {
	const ordinary = "request timed out while collecting TLS observations"
	if got := RedactString(ordinary); got != ordinary {
		t.Errorf("RedactString() = %q, want ordinary text unchanged", got)
	}
}
