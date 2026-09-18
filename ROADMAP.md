# RaxuisCLI - Roadmap Cybersécurité

**Orientation:** Offensive (Pentest/CTF) | **Niveau:** Avancé

---

<!-- BEGIN GENERATED COMMAND CATALOG -->
## Command maturity catalog

Ce tableau est généré depuis les métadonnées validées du binaire. Une commande `experimental` peut être incomplète; une commande `informational` fournit surtout des conseils ou exemples. `TUI: yes` est réservé aux parcours explicitement sûrs de l’interface guidée.

| Command | Summary | Category | Maturity | Safety | TUI |
|---|---|---|---|---|:---:|
| `raxuiscli` | A powerful CLI toolkit | core | `stable` | `safe` | no |
| `raxuiscli audit` | Passive security audits with versioned reports | audit & reporting | `stable` | `safe` | no |
| `raxuiscli audit tls` | Audit TLS/SSL posture and produce a versioned report | audit & reporting | `stable` | `active` | no |
| `raxuiscli audit web` | Passively inspect HTTP security headers and TLS certificates | audit & reporting | `stable` | `passive` | yes |
| `raxuiscli certinfo` | Analyze X.509 certificates | cryptography | `experimental` | `safe` | no |
| `raxuiscli certinfo chain` | Display full certificate chain | cryptography | `experimental` | `safe` | no |
| `raxuiscli certinfo compare` | Compare two certificates | cryptography | `experimental` | `safe` | no |
| `raxuiscli certinfo san` | Extract Subject Alternative Names | cryptography | `experimental` | `safe` | no |
| `raxuiscli certinfo validate` | Validate certificate | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher` | Classical cipher operations (XOR, Vigenere, frequency analysis) | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher atbash` | Atbash cipher (A=Z, B=Y, ...) | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher caesar` | Caesar cipher encrypt/decrypt/brute-force | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher detect` | Detect cipher type | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher freq` | Frequency analysis of text | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher rot13` | ROT13 encode/decode | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher vigenere` | Vigenere cipher encrypt/decrypt | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher vigenere-crack` | Crack Vigenere cipher using Kasiski examination | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher xor` | XOR encrypt/decrypt with key | cryptography | `experimental` | `safe` | no |
| `raxuiscli cipher xor-brute` | Brute force XOR encryption | cryptography | `experimental` | `safe` | no |
| `raxuiscli cloud` | Cloud infrastructure enumeration | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud aws` | AWS enumeration | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud aws metadata` | Check AWS metadata service | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud aws s3` | Enumerate S3 buckets | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud azure` | Azure enumeration | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud azure blob` | Enumerate Azure blob storage | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud azure metadata` | Check Azure metadata service | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud gcp` | GCP enumeration | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud gcp bucket` | Enumerate GCP storage buckets | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud gcp metadata` | Check GCP metadata service | infrastructure | `experimental` | `active` | no |
| `raxuiscli cloud metadata` | Check cloud metadata service | infrastructure | `experimental` | `active` | no |
| `raxuiscli compare` | Compare two versioned audit reports | audit & reporting | `stable` | `safe` | yes |
| `raxuiscli completion` | Generate the autocompletion script for the specified shell | core | `stable` | `safe` | no |
| `raxuiscli completion bash` | Generate the autocompletion script for bash | core | `stable` | `safe` | no |
| `raxuiscli completion fish` | Generate the autocompletion script for fish | core | `stable` | `safe` | no |
| `raxuiscli completion powershell` | Generate the autocompletion script for powershell | core | `stable` | `safe` | no |
| `raxuiscli completion zsh` | Generate the autocompletion script for zsh | core | `stable` | `safe` | no |
| `raxuiscli container` | Container security assessment | infrastructure | `experimental` | `active` | no |
| `raxuiscli container check` | Full container security check | infrastructure | `experimental` | `active` | no |
| `raxuiscli container detect` | Detect container environment | infrastructure | `experimental` | `active` | no |
| `raxuiscli container escape` | Check container escape vectors | infrastructure | `experimental` | `active` | no |
| `raxuiscli container secrets` | Find container secrets | infrastructure | `experimental` | `active` | no |
| `raxuiscli cookie` | Cookie decoding and analysis | web security | `experimental` | `safe` | no |
| `raxuiscli cookie analyze` | Analyze cookie security | web security | `experimental` | `safe` | no |
| `raxuiscli cookie bulk` | Analyze multiple cookies | web security | `experimental` | `safe` | no |
| `raxuiscli cookie decode` | Decode cookie value | web security | `experimental` | `safe` | no |
| `raxuiscli cookie detect` | Detect session type | web security | `experimental` | `safe` | no |
| `raxuiscli cookie express` | Decode Express.js session cookie | web security | `experimental` | `safe` | no |
| `raxuiscli cookie flask` | Decode Flask session cookie | web security | `experimental` | `safe` | no |
| `raxuiscli cookie sensitive` | Check for sensitive data | web security | `experimental` | `safe` | no |
| `raxuiscli creds` | Credential extraction and manipulation | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli creds combo` | Generate credential combinations | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli creds convert` | Convert credential format | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli creds decode` | Decode encoded credentials | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli creds extract` | Extract credentials from file | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli creds merge` | Merge and deduplicate credential files | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli demo` | Run safe local demonstrations without public network access | audit & reporting | `stable` | `safe` | no |
| `raxuiscli demo web` | Audit an intentionally weak local HTTPS fixture | audit & reporting | `stable` | `safe` | yes |
| `raxuiscli dns` | DNS lookup and analysis tools | network | `experimental` | `passive` | no |
| `raxuiscli dns axfr` | Attempt DNS zone transfer | network | `experimental` | `active` | no |
| `raxuiscli dns brute` | Bruteforce subdomains | network | `experimental` | `active` | no |
| `raxuiscli dns lookup` | Perform DNS lookup | network | `experimental` | `passive` | no |
| `raxuiscli dns reverse` | Perform reverse DNS lookup | network | `experimental` | `passive` | no |
| `raxuiscli encode` | Encode text in various formats | utilities | `experimental` | `safe` | no |
| `raxuiscli encode decode` | Decode text from various formats | utilities | `experimental` | `safe` | no |
| `raxuiscli encode rot-brute` | Brute force all ROT-N values | utilities | `experimental` | `safe` | no |
| `raxuiscli entropy` | Calculate file entropy | utilities | `experimental` | `safe` | no |
| `raxuiscli exfil` | Data exfiltration helpers | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli exfil chunk` | Split file into chunks | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli exfil dns` | Generate DNS exfiltration queries | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli exfil encode` | Encode file for exfiltration | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli exfil receiver` | Generate receiver script | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli exfil script` | Generate exfiltration script | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli files` | File operations | utilities | `experimental` | `safe` | no |
| `raxuiscli files checksum` | Calculate file checksums | utilities | `experimental` | `safe` | no |
| `raxuiscli files compress` | Compress files | utilities | `experimental` | `safe` | no |
| `raxuiscli files decrypt` | Decrypt a file | utilities | `experimental` | `safe` | no |
| `raxuiscli files encrypt` | Encrypt a file | utilities | `experimental` | `safe` | no |
| `raxuiscli files extract` | Extract archive | utilities | `experimental` | `safe` | no |
| `raxuiscli files find` | Find files | utilities | `experimental` | `safe` | no |
| `raxuiscli files shred` | Securely delete files | utilities | `experimental` | `dangerous` | no |
| `raxuiscli fuzz` | Web fuzzing tools (directory, parameter, vhost) | web security | `experimental` | `active` | no |
| `raxuiscli fuzz dir` | Directory/file brute force | web security | `experimental` | `active` | no |
| `raxuiscli fuzz param` | Parameter discovery | web security | `experimental` | `active` | no |
| `raxuiscli fuzz vhost` | Virtual host discovery | web security | `experimental` | `active` | no |
| `raxuiscli hash` | Hash text or files | utilities | `experimental` | `safe` | no |
| `raxuiscli hash crack` | Crack hash using wordlist | utilities | `experimental` | `safe` | no |
| `raxuiscli hash identify` | Identify hash type | utilities | `experimental` | `safe` | no |
| `raxuiscli help` | Help about any command | core | `stable` | `safe` | no |
| `raxuiscli hexdump` | Display file contents in hex and ASCII | utilities | `experimental` | `safe` | no |
| `raxuiscli http` | HTTP request tools and security header analysis | web security | `experimental` | `passive` | no |
| `raxuiscli http curl` | Generate curl command | web security | `informational` | `safe` | no |
| `raxuiscli http delete` | Perform HTTP DELETE request | web security | `experimental` | `active` | no |
| `raxuiscli http get` | Perform HTTP GET request | web security | `experimental` | `passive` | no |
| `raxuiscli http head` | Perform HTTP HEAD request | web security | `experimental` | `passive` | no |
| `raxuiscli http headers` | Analyze security headers | web security | `experimental` | `passive` | no |
| `raxuiscli http options` | Perform HTTP OPTIONS request | web security | `experimental` | `active` | no |
| `raxuiscli http post` | Perform HTTP POST request | web security | `experimental` | `active` | no |
| `raxuiscli http put` | Perform HTTP PUT request | web security | `experimental` | `active` | no |
| `raxuiscli http trace` | Trace redirects | web security | `experimental` | `passive` | no |
| `raxuiscli interactive` | Launch the guided terminal interface | audit & reporting | `stable` | `safe` | no |
| `raxuiscli jwt` | JWT token operations (decode, forge, crack, attack) | cryptography | `experimental` | `safe` | no |
| `raxuiscli jwt check` | Check JWT for vulnerabilities | cryptography | `experimental` | `safe` | no |
| `raxuiscli jwt crack` | Brute force JWT secret | cryptography | `experimental` | `safe` | no |
| `raxuiscli jwt decode` | Decode JWT without verification | cryptography | `experimental` | `safe` | no |
| `raxuiscli jwt forge` | Create a new JWT token | cryptography | `experimental` | `safe` | no |
| `raxuiscli jwt none-attack` | Exploit algorithm 'none' vulnerability | cryptography | `experimental` | `active` | no |
| `raxuiscli jwt verify` | Verify JWT signature | cryptography | `experimental` | `safe` | no |
| `raxuiscli k8s` | Kubernetes security assessment | infrastructure | `experimental` | `active` | no |
| `raxuiscli k8s check` | Full Kubernetes security check | infrastructure | `experimental` | `active` | no |
| `raxuiscli k8s commands` | Show useful kubectl commands | infrastructure | `informational` | `passive` | no |
| `raxuiscli k8s detect` | Detect Kubernetes environment | infrastructure | `experimental` | `active` | no |
| `raxuiscli k8s enum` | Enumerate accessible resources | infrastructure | `experimental` | `active` | no |
| `raxuiscli k8s privesc` | Check privilege escalation paths | infrastructure | `experimental` | `active` | no |
| `raxuiscli k8s secrets` | List accessible secrets | infrastructure | `experimental` | `active` | no |
| `raxuiscli kerberos` | Kerberos attack helpers | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli kerberos asrep` | AS-REP Roasting commands | offensive security | `informational` | `safe` | no |
| `raxuiscli kerberos golden` | Golden ticket commands | offensive security | `informational` | `safe` | no |
| `raxuiscli kerberos parse` | Parse Kerberos hash | offensive security | `experimental` | `safe` | no |
| `raxuiscli kerberos roast` | Kerberoasting commands | offensive security | `informational` | `safe` | no |
| `raxuiscli kerberos silver` | Silver ticket commands | offensive security | `informational` | `safe` | no |
| `raxuiscli keygen` | Generate cryptographic keys and certificates | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen aes` | Generate AES key | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen cert` | Generate self-signed certificate | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen ecdsa` | Generate ECDSA key pair | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen ed25519` | Generate Ed25519 key pair | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen random` | Generate random bytes | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen rsa` | Generate RSA key pair | cryptography | `experimental` | `safe` | no |
| `raxuiscli keygen ssh` | Generate SSH key pair | cryptography | `experimental` | `safe` | no |
| `raxuiscli ldap` | Active Directory LDAP enumeration | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli ldap enum` | Full AD enumeration | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli ldap test` | Test LDAP connectivity | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli ldap users` | Enumerate AD users | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli metadata` | Extract file metadata | utilities | `experimental` | `safe` | no |
| `raxuiscli metadata strip` | Strip metadata from a file | utilities | `experimental` | `safe` | no |
| `raxuiscli ntlm` | NTLM hash operations | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli ntlm crack` | Crack NTLM hash | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli ntlm hash` | Generate NTLM hash | offensive security | `experimental` | `safe` | no |
| `raxuiscli ntlm identify` | Identify hash type | offensive security | `experimental` | `safe` | no |
| `raxuiscli ntlm parse` | Parse NTLM dump format | offensive security | `experimental` | `safe` | no |
| `raxuiscli ntlm pth` | Generate pass-the-hash commands | offensive security | `informational` | `safe` | no |
| `raxuiscli obfuscate` | Payload obfuscation | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli obfuscate bash` | Obfuscate Bash commands | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli obfuscate ps` | Obfuscate PowerShell | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli obfuscate shellcode` | Obfuscate shellcode | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli obfuscate shellcode-hex` | Obfuscate shellcode from hex string | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli obfuscate string` | Obfuscate string | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli persist` | Persistence mechanism helpers | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli persist check` | Check existing persistence | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli persist cron` | Generate cron persistence | offensive security | `experimental` | `safe` | no |
| `raxuiscli persist launchd` | Generate launchd plist (macOS) | offensive security | `experimental` | `safe` | no |
| `raxuiscli persist list` | List persistence techniques | offensive security | `informational` | `safe` | no |
| `raxuiscli persist systemd` | Generate systemd service | offensive security | `experimental` | `safe` | no |
| `raxuiscli pivot` | Network pivoting and proxying | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli pivot forward` | TCP port forwarding | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli pivot socks5` | Start SOCKS5 proxy | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli pivot test` | Test remote connectivity | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli poison` | Network poisoning helpers | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli poison analyze` | Analyze network for poisoning opportunities | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli poison arp` | ARP poisoning commands | offensive security | `informational` | `safe` | no |
| `raxuiscli poison dhcp` | DHCP poisoning information | offensive security | `informational` | `safe` | no |
| `raxuiscli poison llmnr` | LLMNR poisoning commands | offensive security | `informational` | `safe` | no |
| `raxuiscli poison mdns` | mDNS poisoning commands | offensive security | `informational` | `safe` | no |
| `raxuiscli poison nbtns` | NBT-NS poisoning commands | offensive security | `informational` | `safe` | no |
| `raxuiscli poison protocols` | List poisoning protocols | offensive security | `informational` | `safe` | no |
| `raxuiscli poison responder` | Responder command generator | offensive security | `informational` | `safe` | no |
| `raxuiscli ports` | Check open ports on a host | utilities | `experimental` | `active` | no |
| `raxuiscli privesc` | Privilege escalation enumeration | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc capabilities` | Check Linux capabilities | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc check` | Run all privilege escalation checks | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc cron` | Check cron jobs | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc info` | Display system information | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc passwords` | Check password files | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc sudo` | Check sudo configuration | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc suid` | Check SUID/SGID binaries | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli privesc writable` | Check writable paths | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli pwgen` | Generate secure passwords | utilities | `experimental` | `safe` | no |
| `raxuiscli pwgen generate` | Generate password(s) | utilities | `experimental` | `safe` | no |
| `raxuiscli recon` | Banner grabbing and service detection | network | `experimental` | `passive` | no |
| `raxuiscli smb` | SMB enumeration and analysis | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli smb null` | Test null session | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli smb scan` | Scan SMB service | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli smb shares` | Enumerate SMB shares | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli strings` | Extract printable strings from files | utilities | `experimental` | `safe` | no |
| `raxuiscli tlsscan` | Audit a server's TLS/SSL posture | cryptography | `experimental` | `active` | no |
| `raxuiscli todo` | Manage your todo list | utilities | `experimental` | `safe` | no |
| `raxuiscli todo add` | Add a new todo item | utilities | `experimental` | `safe` | no |
| `raxuiscli todo complete` | Mark a todo item as complete | utilities | `experimental` | `safe` | no |
| `raxuiscli todo incomplete` | Mark a todo item as incomplete | utilities | `experimental` | `safe` | no |
| `raxuiscli todo list` | List all todo items | utilities | `experimental` | `safe` | no |
| `raxuiscli tunnel` | Network tunneling utilities | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli tunnel decode` | Decode tunneled data | offensive security | `experimental` | `safe` | no |
| `raxuiscli tunnel dns` | DNS tunneling information | offensive security | `informational` | `safe` | no |
| `raxuiscli tunnel encode` | Encode data for tunneling | offensive security | `experimental` | `safe` | no |
| `raxuiscli tunnel tcp` | TCP port forwarding | offensive security | `experimental` | `dangerous` | no |
| `raxuiscli version` | Print version, commit and build information | utilities | `experimental` | `safe` | no |
| `raxuiscli vuln` | Vulnerability scanning and testing | web security | `experimental` | `active` | no |
| `raxuiscli vuln cors` | Test for CORS misconfiguration | web security | `experimental` | `active` | no |
| `raxuiscli vuln graphql` | Test GraphQL endpoint security | web security | `experimental` | `active` | no |
| `raxuiscli vuln headers` | Check security headers | web security | `experimental` | `active` | no |
| `raxuiscli vuln host` | Test for Host header injection | web security | `experimental` | `active` | no |
| `raxuiscli vuln lfi` | Test for Local File Inclusion vulnerabilities | web security | `experimental` | `active` | no |
| `raxuiscli vuln nosqli` | Test for NoSQL injection | web security | `experimental` | `active` | no |
| `raxuiscli vuln payloads` | List vulnerability payloads | web security | `informational` | `safe` | no |
| `raxuiscli vuln race` | Test for race condition vulnerabilities | web security | `experimental` | `active` | no |
| `raxuiscli vuln scan` | Quick vulnerability scan | web security | `experimental` | `active` | no |
| `raxuiscli vuln sqli` | Test for SQL injection vulnerabilities | web security | `experimental` | `active` | no |
| `raxuiscli vuln xss` | Test for XSS vulnerabilities | web security | `experimental` | `active` | no |
| `raxuiscli vuln xxe` | Test for XXE vulnerabilities | web security | `experimental` | `active` | no |
| `raxuiscli whois` | WHOIS lookup for domains, IPs, and ASNs | network | `experimental` | `passive` | no |
<!-- END GENERATED COMMAND CATALOG -->

---

## 🔧 Build & Test

```bash
# Build
go build -o bin/raxuiscli .

# Test commands - Network
./bin/raxuiscli dns lookup google.com
./bin/raxuiscli whois example.com
./bin/raxuiscli recon example.com:80

# Test commands - Red Team
./bin/raxuiscli privesc check
./bin/raxuiscli ntlm hash "Password123"
./bin/raxuiscli cloud aws s3 companyname
./bin/raxuiscli kerberos roast -d corp.local

# Test commands - Cryptography
./bin/raxuiscli cipher xor "secret" --key "key"
./bin/raxuiscli jwt decode "eyJ..."
./bin/raxuiscli keygen aes --bits 256
./bin/raxuiscli certinfo example.com

# Test commands - Web Security
./bin/raxuiscli http headers https://example.com
./bin/raxuiscli fuzz dir https://example.com --common
./bin/raxuiscli vuln scan "https://site.com?id=1"
./bin/raxuiscli cookie decode "eyJhZG1pbiI6dHJ1ZX0="

# Audit, reporting & guided interface (loopback-only demo, no public network)
./bin/raxuiscli demo web --output json
./bin/raxuiscli demo web --output html --output-file /tmp/raxuis-demo.html
./bin/raxuiscli interactive
```

---

## 📁 Structure du Projet

```
RaxuisCLI/
├── cmd/                    # Définitions des commandes
│   ├── dns.go              # Sprint 1 - Réseau
│   ├── whois.go
│   ├── recon.go
│   ├── ldap.go             # Sprint 1.5 - Red Team
│   ├── privesc.go
│   ├── creds.go
│   ├── smb.go
│   ├── cloud.go
│   ├── tunnel.go
│   ├── pivot.go
│   ├── poison.go
│   ├── ntlm.go
│   ├── kerberos.go
│   ├── obfuscate.go
│   ├── exfil.go
│   ├── persist.go
│   ├── container.go
│   ├── k8s.go
│   ├── cipher.go           # Sprint 2 - Crypto
│   ├── jwt.go
│   ├── keygen.go
│   ├── certinfo.go
│   ├── http.go             # Sprint 3 - Web Security
│   ├── fuzz.go
│   ├── vuln.go
│   └── cookie.go
├── internal/               # Logique métier
│   ├── dns/
│   ├── whois/
│   ├── recon/
│   ├── ldap/
│   ├── privesc/
│   ├── creds/
│   ├── smb/
│   ├── cloud/
│   ├── tunnel/
│   ├── pivot/
│   ├── poison/
│   ├── ntlm/
│   ├── kerberos/
│   ├── obfuscate/
│   ├── exfil/
│   ├── persist/
│   ├── container/
│   ├── k8s/
│   ├── cipher/
│   ├── jwt/
│   ├── keygen/
│   ├── certinfo/
│   ├── http/
│   ├── fuzz/
│   ├── vuln/
│   └── cookie/
└── main.go
```
