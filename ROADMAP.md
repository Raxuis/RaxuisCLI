# RaxuisCLI - Roadmap Cybersécurité

**Orientation:** Offensive (Pentest/CTF) | **Niveau:** Avancé

---

<!-- BEGIN GENERATED COMMAND CATALOG -->
## Command maturity catalog

Ce tableau est généré depuis les métadonnées validées du binaire. Une commande `experimental` peut être incomplète; une commande `informational` fournit surtout des conseils ou exemples. `TUI: yes` est réservé aux parcours explicitement sûrs de l’interface guidée.

| Command | Summary | Category | Maturity | Safety | TUI | Output | File | Quiet (text) | Fail-on | Verbose |
|---|---|---|---|---|:---:|---|:---:|:---:|:---:|:---:|
| `raxuiscli` | A powerful CLI toolkit | core | `stable` | `safe` | no | text, json | true | true | false | false |
| `raxuiscli audit` | Passive security audits with versioned reports | audit & reporting | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli audit all` | Combine web, DNS, and TLS posture audits in one versioned report | audit & reporting | `stable` | `active` | no | text, json, html | true | true | true | false |
| `raxuiscli audit dns` | Audit a domain's DNS/email posture and produce a versioned report | audit & reporting | `stable` | `active` | no | text, json, html | true | true | true | false |
| `raxuiscli audit tls` | Audit TLS/SSL posture and produce a versioned report | audit & reporting | `stable` | `active` | no | text, json, html | true | true | true | false |
| `raxuiscli audit web` | Passively inspect HTTP security headers and TLS certificates | audit & reporting | `stable` | `passive` | yes | text, json, html | true | true | true | false |
| `raxuiscli certinfo` | Analyze X.509 certificates | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli certinfo chain` | Display full certificate chain | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli certinfo compare` | Compare two certificates | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli certinfo san` | Extract Subject Alternative Names | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli certinfo validate` | Validate certificate | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher` | Classical cipher operations (XOR, Vigenere, frequency analysis) | cryptography | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli cipher atbash` | Atbash cipher (A=Z, B=Y, ...) | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher caesar` | Caesar cipher encrypt/decrypt/brute-force | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher detect` | Detect cipher type | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher freq` | Frequency analysis of text | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher rot13` | ROT13 encode/decode | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher vigenere` | Vigenere cipher encrypt/decrypt | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher vigenere-crack` | Crack Vigenere cipher using Kasiski examination | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher xor` | XOR encrypt/decrypt with key | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cipher xor-brute` | Brute force XOR encryption | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cloud` | Cloud infrastructure enumeration | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud aws` | AWS enumeration | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud aws metadata` | Check AWS metadata service | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud aws s3` | Enumerate S3 buckets | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud azure` | Azure enumeration | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud azure blob` | Enumerate Azure blob storage | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud azure metadata` | Check Azure metadata service | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud gcp` | GCP enumeration | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud gcp bucket` | Enumerate GCP storage buckets | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud gcp metadata` | Check GCP metadata service | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cloud metadata` | Check cloud metadata service | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli compare` | Compare two versioned audit reports | audit & reporting | `stable` | `safe` | yes | text, json, html | true | true | false | false |
| `raxuiscli completion` | Generate the autocompletion script for the specified shell | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli completion bash` | Generate the autocompletion script for bash | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli completion fish` | Generate the autocompletion script for fish | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli completion powershell` | Generate the autocompletion script for powershell | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli completion zsh` | Generate the autocompletion script for zsh | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli container` | Container security assessment | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli container check` | Full container security check | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli container detect` | Detect container environment | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli container escape` | Check container escape vectors | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli container secrets` | Find container secrets | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli cookie` | Cookie decoding and analysis | web security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli cookie analyze` | Analyze cookie security | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie bulk` | Analyze multiple cookies | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie decode` | Decode cookie value | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie detect` | Detect session type | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie express` | Decode Express.js session cookie | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie flask` | Decode Flask session cookie | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli cookie sensitive` | Check for sensitive data | web security | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli creds` | Credential extraction and manipulation | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli creds combo` | Generate credential combinations | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli creds convert` | Convert credential format | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli creds decode` | Decode encoded credentials | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli creds extract` | Extract credentials from file | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli creds merge` | Merge and deduplicate credential files | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli demo` | Run safe local demonstrations without public network access | audit & reporting | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli demo web` | Audit an intentionally weak local HTTPS fixture | audit & reporting | `stable` | `safe` | yes | text, json, html | true | true | true | false |
| `raxuiscli dns` | DNS lookup and analysis tools | network | `experimental` | `passive` | no | text | true | false | false | false |
| `raxuiscli dns axfr` | Attempt DNS zone transfer | network | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli dns brute` | Bruteforce subdomains | network | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli dns lookup` | Perform DNS lookup | network | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli dns reverse` | Perform reverse DNS lookup | network | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli doctor` | Check local runtime and optional tools without changing the environment | core | `experimental` | `safe` | no | text, json | true | true | false | false |
| `raxuiscli encode` | Encode text in various formats | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli encode decode` | Decode text from various formats | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli encode rot-brute` | Brute force all ROT-N values | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli entropy` | Calculate file entropy | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli exfil` | Data exfiltration helpers | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli exfil chunk` | Split file into chunks | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli exfil dns` | Generate DNS exfiltration queries | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli exfil encode` | Encode file for exfiltration | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli exfil receiver` | Generate receiver script | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli exfil script` | Generate exfiltration script | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli files` | File operations | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli files checksum` | Calculate file checksums | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli files compress` | Compress files | utilities | `experimental` | `safe` | no | text | true | false | false | true |
| `raxuiscli files decrypt` | Decrypt a file | utilities | `experimental` | `safe` | no | text | true | false | false | true |
| `raxuiscli files encrypt` | Encrypt a file | utilities | `experimental` | `safe` | no | text | true | false | false | true |
| `raxuiscli files extract` | Extract archive | utilities | `experimental` | `safe` | no | text | true | false | false | true |
| `raxuiscli files find` | Find files | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli files shred` | Securely delete files | utilities | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli fuzz` | Web fuzzing tools (directory, parameter, vhost) | web security | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli fuzz dir` | Directory/file brute force | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli fuzz param` | Parameter discovery | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli fuzz vhost` | Virtual host discovery | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli hash` | Hash text or files | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli hash crack` | Crack hash using wordlist | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli hash identify` | Identify hash type (with hashcat/john hints) | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli hashid` | Identify hash type (alias of 'hash identify') | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli help` | Help about any command | core | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli hexdump` | Display file contents in hex and ASCII | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli http` | HTTP request tools and security header analysis | web security | `experimental` | `passive` | no | text | true | false | false | false |
| `raxuiscli http curl` | Generate curl command | web security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli http delete` | Perform HTTP DELETE request | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli http get` | Perform HTTP GET request | web security | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli http head` | Perform HTTP HEAD request | web security | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli http headers` | Analyze security headers | web security | `experimental` | `passive` | no | text, json | true | false | false | true |
| `raxuiscli http options` | Perform HTTP OPTIONS request | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli http post` | Perform HTTP POST request | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli http put` | Perform HTTP PUT request | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli http trace` | Trace redirects | web security | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli interactive` | Launch the guided terminal interface | audit & reporting | `stable` | `safe` | no | text | true | false | false | false |
| `raxuiscli jwt` | JWT token operations (decode, forge, crack, attack) | cryptography | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli jwt check` | Check JWT for vulnerabilities | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli jwt crack` | Brute force JWT secret | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli jwt decode` | Decode JWT without verification | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli jwt forge` | Create a new JWT token | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli jwt none-attack` | Exploit algorithm 'none' vulnerability | cryptography | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli jwt verify` | Verify JWT signature | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli k8s` | Kubernetes security assessment | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli k8s check` | Full Kubernetes security check | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli k8s commands` | Show useful kubectl commands | infrastructure | `informational` | `passive` | no | text | true | false | false | false |
| `raxuiscli k8s detect` | Detect Kubernetes environment | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli k8s enum` | Enumerate accessible resources | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli k8s privesc` | Check privilege escalation paths | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli k8s secrets` | List accessible secrets | infrastructure | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli kerberos` | Kerberos attack helpers | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli kerberos asrep` | AS-REP Roasting commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli kerberos golden` | Golden ticket commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli kerberos parse` | Parse Kerberos hash | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli kerberos roast` | Kerberoasting commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli kerberos silver` | Silver ticket commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli keygen` | Generate cryptographic keys and certificates | cryptography | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli keygen aes` | Generate AES key | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen cert` | Generate self-signed certificate | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen ecdsa` | Generate ECDSA key pair | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen ed25519` | Generate Ed25519 key pair | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen random` | Generate random bytes | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen rsa` | Generate RSA key pair | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli keygen ssh` | Generate SSH key pair | cryptography | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli ldap` | Active Directory LDAP enumeration | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli ldap enum` | Full AD enumeration | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli ldap test` | Test LDAP connectivity | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli ldap users` | Enumerate AD users | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli metadata` | Extract file metadata | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli metadata strip` | Strip metadata from a file | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli ntlm` | NTLM hash operations | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli ntlm crack` | Crack NTLM hash | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli ntlm hash` | Generate NTLM hash | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli ntlm identify` | Identify hash type | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli ntlm parse` | Parse NTLM dump format | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli ntlm pth` | Generate pass-the-hash commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli obfuscate` | Payload obfuscation | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli obfuscate bash` | Obfuscate Bash commands | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli obfuscate ps` | Obfuscate PowerShell | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli obfuscate shellcode` | Obfuscate shellcode | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli obfuscate shellcode-hex` | Obfuscate shellcode from hex string | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli obfuscate string` | Obfuscate string | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli persist` | Persistence mechanism helpers | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli persist check` | Check existing persistence | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli persist cron` | Generate cron persistence | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli persist launchd` | Generate launchd plist (macOS) | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli persist list` | List persistence techniques | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli persist systemd` | Generate systemd service | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli pivot` | Network pivoting and proxying | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli pivot forward` | TCP port forwarding | offensive security | `experimental` | `dangerous` | no | text | false | false | false | false |
| `raxuiscli pivot socks5` | Start SOCKS5 proxy | offensive security | `experimental` | `dangerous` | no | text | false | false | false | false |
| `raxuiscli pivot test` | Test remote connectivity | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli poison` | Network poisoning helpers | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli poison analyze` | Analyze network for poisoning opportunities | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli poison arp` | ARP poisoning commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison dhcp` | DHCP poisoning information | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison llmnr` | LLMNR poisoning commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison mdns` | mDNS poisoning commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison nbtns` | NBT-NS poisoning commands | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison protocols` | List poisoning protocols | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli poison responder` | Responder command generator | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli ports` | Check open ports on a host | utilities | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli privesc` | Privilege escalation enumeration | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc capabilities` | Check Linux capabilities | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc check` | Run all privilege escalation checks | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc cron` | Check cron jobs | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc info` | Display system information | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc passwords` | Check password files | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc sudo` | Check sudo configuration | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc suid` | Check SUID/SGID binaries | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli privesc writable` | Check writable paths | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli pwgen` | Generate secure passwords | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli pwgen generate` | Generate password(s) | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli recon` | Banner grabbing and service detection | network | `experimental` | `passive` | no | text, json | true | false | false | false |
| `raxuiscli scan` | Concurrent host & service discovery (attack-surface mapper) | network | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli smb` | SMB enumeration and analysis | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli smb null` | Test null session | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli smb scan` | Scan SMB service | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli smb shares` | Enumerate SMB shares | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli spray` | Low-and-slow AD password spraying (LDAP) | offensive security | `experimental` | `dangerous` | no | text, json | true | false | false | false |
| `raxuiscli strings` | Extract printable strings from files | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli tlsscan` | Audit a server's TLS/SSL posture | cryptography | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli todo` | Manage your todo list | utilities | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli todo add` | Add a new todo item | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli todo complete` | Mark a todo item as complete | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli todo incomplete` | Mark a todo item as incomplete | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli todo list` | List all todo items | utilities | `experimental` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli tunnel` | Network tunneling utilities | offensive security | `experimental` | `dangerous` | no | text | true | false | false | false |
| `raxuiscli tunnel decode` | Decode tunneled data | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli tunnel dns` | DNS tunneling information | offensive security | `informational` | `safe` | no | text | true | false | false | false |
| `raxuiscli tunnel encode` | Encode data for tunneling | offensive security | `experimental` | `safe` | no | text | true | false | false | false |
| `raxuiscli tunnel tcp` | TCP port forwarding | offensive security | `experimental` | `dangerous` | no | text | false | false | false | false |
| `raxuiscli version` | Print version, commit and build information | core | `experimental` | `safe` | no | text, json | true | true | false | false |
| `raxuiscli vuln` | Vulnerability scanning and testing | web security | `experimental` | `active` | no | text | true | false | false | false |
| `raxuiscli vuln cors` | Test for CORS misconfiguration | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln graphql` | Test GraphQL endpoint security | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln headers` | Check security headers | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln host` | Test for Host header injection | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln lfi` | Test for Local File Inclusion vulnerabilities | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln nosqli` | Test for NoSQL injection | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln payloads` | List vulnerability payloads | web security | `informational` | `safe` | no | text, json | true | false | false | false |
| `raxuiscli vuln race` | Test for race condition vulnerabilities | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln scan` | Quick vulnerability scan | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln sqli` | Test for SQL injection vulnerabilities | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln xss` | Test for XSS vulnerabilities | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli vuln xxe` | Test for XXE vulnerabilities | web security | `experimental` | `active` | no | text, json | true | false | false | false |
| `raxuiscli whois` | WHOIS lookup for domains, IPs, and ASNs | network | `experimental` | `passive` | no | text, json | true | false | false | false |
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
