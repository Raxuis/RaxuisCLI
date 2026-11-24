package catalog

import "strings"

type Capabilities struct {
	JSON         bool `json:"json"`
	HTML         bool `json:"html"`
	OutputFile   bool `json:"output_file"`
	Verbose      bool `json:"verbose"`
	Quiet        bool `json:"quiet"`
	FailOn       bool `json:"fail_on"`
	NativeOutput bool `json:"native_output"`
}

func CapabilitiesFor(path string) Capabilities {
	c := Capabilities{OutputFile: true}
	switch path {
	case "raxuiscli audit web", "raxuiscli audit dns", "raxuiscli audit tls", "raxuiscli audit all", "raxuiscli demo web", "raxuiscli compare":
		return Capabilities{JSON: true, HTML: true, OutputFile: true, Quiet: true, FailOn: path != "raxuiscli compare", NativeOutput: true}
	case "raxuiscli interactive":
		return Capabilities{OutputFile: true, NativeOutput: true}
	case "raxuiscli pivot socks5", "raxuiscli pivot forward", "raxuiscli tunnel tcp":
		return Capabilities{}
	case "raxuiscli", "raxuiscli doctor", "raxuiscli version":
		c.JSON = true
		c.Quiet = true
	}
	c.Verbose = path == "raxuiscli http headers" || path == "raxuiscli files encrypt" || path == "raxuiscli files decrypt" || path == "raxuiscli files compress" || path == "raxuiscli files extract"
	if jsonCommands[path] {
		c.JSON = true
	}
	return c
}

var jsonCommands = func() map[string]bool {
	result := map[string]bool{}
	for _, path := range strings.Split(`spray
fuzz dir
fuzz param
fuzz vhost
vuln scan
vuln xss
vuln sqli
vuln lfi
vuln headers
vuln payloads
vuln cors
vuln nosqli
vuln xxe
vuln graphql
vuln host
vuln race
jwt decode
jwt verify
jwt forge
jwt crack
jwt none-attack
jwt check
keygen rsa
keygen ecdsa
keygen ed25519
keygen ssh
keygen cert
keygen aes
keygen random
cookie decode
cookie flask
cookie express
cookie bulk
cipher xor
cipher xor-brute
cipher vigenere
cipher vigenere-crack
cipher detect
todo add
todo list
todo complete
todo incomplete
encode
encode decode
encode rot-brute
hash
hash crack
hash identify
hashid
pwgen
pwgen generate
entropy
metadata
strings
ports
scan
recon
whois
dns lookup
dns reverse
dns axfr
dns brute
certinfo
certinfo chain
certinfo compare
certinfo san
certinfo validate
tlsscan
http get
http post
http put
http delete
http head
http options
http trace
http headers
cookie analyze
cookie sensitive
cookie detect
cipher caesar
cipher rot13
cipher atbash
cipher freq`, "\n") {
		result["raxuiscli "+path] = true
	}
	return result
}()

func (c Capabilities) Formats() string {
	formats := []string{"text"}
	if c.JSON {
		formats = append(formats, "json")
	}
	if c.HTML {
		formats = append(formats, "html")
	}
	return strings.Join(formats, ", ")
}
