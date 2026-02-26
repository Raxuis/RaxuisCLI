# RaxuisCLI - Roadmap Cybersécurité

**Orientation:** Offensive (Pentest/CTF) | **Niveau:** Avancé

---

## ✅ Sprint 1: Réseau (COMPLÉTÉ)

| Commande | Description | Status |
|----------|-------------|--------|
| `dns` | DNS lookup, zone transfer, subdomain brute | ✅ Done |
| `whois` | Domain/IP/ASN information | ✅ Done |
| `recon` | Banner grabbing, service detection | ✅ Done |

---

## ✅ Sprint 1.5: Red Team Tools (COMPLÉTÉ)

### Haute Priorité

| Commande | Description | Status |
|----------|-------------|--------|
| `ldap` | Active Directory enumeration | ✅ Done |
| `privesc` | Privilege escalation checks | ✅ Done |
| `creds` | Credential extraction & analysis | ✅ Done |
| `smb` | SMB shares, spider, relay | ✅ Done |
| `cloud` | AWS/Azure/GCP enumeration | ✅ Done |

### Réseau & Pivoting

| Commande | Description | Status |
|----------|-------------|--------|
| `tunnel` | DNS/ICMP/HTTP tunneling | ✅ Done |
| `pivot` | SOCKS5 proxy, port forwarding | ✅ Done |
| `poison` | LLMNR/mDNS/NetBIOS poisoning | ✅ Done |

### Authentification

| Commande | Description | Status |
|----------|-------------|--------|
| `ntlm` | NTLM cracking, pass-the-hash, relay | ✅ Done |
| `kerberos` | AS-REP roasting, Kerberoasting | ✅ Done |

### Utilitaires Offensifs

| Commande | Description | Status |
|----------|-------------|--------|
| `obfuscate` | PowerShell/shellcode obfuscation | ✅ Done |
| `exfil` | Data exfiltration helpers | ✅ Done |
| `persist` | Persistence mechanisms | ✅ Done |

### Cloud & Containers

| Commande | Description | Status |
|----------|-------------|--------|
| `container` | Container escape, secrets | ✅ Done |
| `k8s` | Kubernetes pentesting | ✅ Done |

---

## ⏳ Sprint 2: Cryptographie

| Commande | Description | Status |
|----------|-------------|--------|
| `cipher` | XOR, Vigenère, frequency analysis | ⏳ Pending |
| `jwt` | JWT decode/forge/crack | ⏳ Pending |
| `keygen` | Generate RSA/SSH/certs | ⏳ Pending |
| `certinfo` | Certificate analysis | ⏳ Pending |

---

## ⏳ Sprint 3: Sécurité Web

| Commande | Description | Status |
|----------|-------------|--------|
| `http` | Custom HTTP requests, headers analysis | ⏳ Pending |
| `fuzz` | Directory/param/vhost fuzzing | ⏳ Pending |
| `vuln` | XSS/SQLi/LFI detection | ⏳ Pending |
| `cookie` | Cookie decode & analysis | ⏳ Pending |

---

## ⏳ Sprint 4: Analyse Binaires

| Commande | Description | Status |
|----------|-------------|--------|
| `bininfo` | PE/ELF/Mach-O analysis | ⏳ Pending |
| `stego` | Steganography detect/extract | ⏳ Pending |
| `ioc` | IoC extraction, YARA | ⏳ Pending |

---

## ⏳ Sprint 5: Utilitaires

| Commande | Description | Status |
|----------|-------------|--------|
| `wordlist` | Generate/mutate wordlists | ⏳ Pending |
| `payload` | Reverse shells, XSS, SQLi generators | ⏳ Pending |

---

## 📊 Progression Globale

- **Sprint 1 (Réseau):** 3/3 ✅
- **Sprint 1.5 (Red Team):** 15/15 ✅
- **Sprint 2 (Crypto):** 0/4
- **Sprint 3 (Web):** 0/4
- **Sprint 4 (Binaires):** 0/3
- **Sprint 5 (Utils):** 0/2

**Total: 18 / 31 commandes implémentées (58%)**

---

## 🔧 Build & Test

```bash
# Build
go build -o bin/raxuiscli .

# Test commands
./bin/raxuiscli dns lookup google.com
./bin/raxuiscli whois example.com
./bin/raxuiscli recon example.com:80
./bin/raxuiscli privesc check
./bin/raxuiscli ntlm hash "Password123"
./bin/raxuiscli cloud aws s3 companyname
./bin/raxuiscli kerberos roast -d corp.local
```

---

## 📁 Structure du Projet

```
RaxuisCLI/
├── cmd/                    # Définitions des commandes
│   ├── dns.go
│   ├── whois.go
│   ├── recon.go
│   ├── ldap.go
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
│   └── k8s.go
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
│   └── k8s/
└── main.go
```
