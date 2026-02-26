# RaxuisCLI - Roadmap Cybersécurité

**Orientation:** Offensive (Pentest/CTF) | **Niveau:** Avancé

---

## ✅ Sprint 1: Réseau (COMPLÉTÉ)

| Commande | Description                                | Status |
|----------|--------------------------------------------|--------|
| `dns`    | DNS lookup, zone transfer, subdomain brute | ✅ Done |
| `whois`  | Domain/IP/ASN information                  | ✅ Done |
| `recon`  | Banner grabbing, service detection         | ✅ Done |

---

## ✅ Sprint 1.5: Red Team Tools (COMPLÉTÉ)

### Haute Priorité

| Commande  | Description                      | Status |
|-----------|----------------------------------|--------|
| `ldap`    | Active Directory enumeration     | ✅ Done |
| `privesc` | Privilege escalation checks      | ✅ Done |
| `creds`   | Credential extraction & analysis | ✅ Done |
| `smb`     | SMB shares, spider, relay        | ✅ Done |
| `cloud`   | AWS/Azure/GCP enumeration        | ✅ Done |

### Réseau & Pivoting

| Commande | Description                   | Status |
|----------|-------------------------------|--------|
| `tunnel` | DNS/ICMP/HTTP tunneling       | ✅ Done |
| `pivot`  | SOCKS5 proxy, port forwarding | ✅ Done |
| `poison` | LLMNR/mDNS/NetBIOS poisoning  | ✅ Done |

### Authentification

| Commande   | Description                         | Status |
|------------|-------------------------------------|--------|
| `ntlm`     | NTLM cracking, pass-the-hash, relay | ✅ Done |
| `kerberos` | AS-REP roasting, Kerberoasting      | ✅ Done |

### Utilitaires Offensifs

| Commande    | Description                      | Status |
|-------------|----------------------------------|--------|
| `obfuscate` | PowerShell/shellcode obfuscation | ✅ Done |
| `exfil`     | Data exfiltration helpers        | ✅ Done |
| `persist`   | Persistence mechanisms           | ✅ Done |

### Cloud & Containers

| Commande    | Description               | Status |
|-------------|---------------------------|--------|
| `container` | Container escape, secrets | ✅ Done |
| `k8s`       | Kubernetes pentesting     | ✅ Done |

---

## ✅ Sprint 2: Cryptographie (COMPLÉTÉ)

| Commande   | Description                               | Status |
|------------|-------------------------------------------|--------|
| `cipher`   | XOR, Vigenère, Caesar, frequency analysis | ✅ Done |
| `jwt`      | JWT decode/forge/crack/none-attack        | ✅ Done |
| `keygen`   | Generate RSA/ECDSA/Ed25519/SSH/certs/AES  | ✅ Done |
| `certinfo` | Certificate analysis, chain, validation   | ✅ Done |

---

## ✅ Sprint 3: Sécurité Web (COMPLÉTÉ)

| Commande | Description                            | Status  |
|----------|----------------------------------------|---------|
| `http`   | Custom HTTP requests, headers analysis | ✅ Done |
| `fuzz`   | Directory/param/vhost fuzzing          | ✅ Done |
| `vuln`   | XSS/SQLi/LFI detection                 | ✅ Done |
| `cookie` | Cookie decode & analysis               | ✅ Done |

---

## ⏳ Sprint 4: Analyse Binaires

| Commande  | Description                  | Status    |
|-----------|------------------------------|-----------|
| `bininfo` | PE/ELF/Mach-O analysis       | ⏳ Pending |
| `stego`   | Steganography detect/extract | ⏳ Pending |
| `ioc`     | IoC extraction, YARA         | ⏳ Pending |

---

## ⏳ Sprint 5: Utilitaires

| Commande   | Description                          | Status    |
|------------|--------------------------------------|-----------|
| `wordlist` | Generate/mutate wordlists            | ⏳ Pending |
| `payload`  | Reverse shells, XSS, SQLi generators | ⏳ Pending |

---

## 📊 Progression Globale

- **Sprint 1 (Réseau):** 3/3 ✅
- **Sprint 1.5 (Red Team):** 15/15 ✅
- **Sprint 2 (Crypto):** 4/4 ✅
- **Sprint 3 (Web):** 4/4 ✅
- **Sprint 4 (Binaires):** 0/3
- **Sprint 5 (Utils):** 0/2

**Total: 26 / 31 commandes implémentées (84%)**

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
