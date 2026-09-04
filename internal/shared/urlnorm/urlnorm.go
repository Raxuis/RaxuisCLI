// Package urlnorm normalizes user-supplied target strings into absolute URLs.
package urlnorm

import "strings"

// EnsureScheme prefixes raw with "https://" if it doesn't already start
// with an http:// or https:// scheme, so commands can accept targets like
// "example.com" as well as full URLs.
func EnsureScheme(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "https://" + raw
}
