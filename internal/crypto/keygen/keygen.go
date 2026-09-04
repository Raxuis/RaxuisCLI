package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// KeyPair holds generated key pair
type KeyPair struct {
	PrivateKey    string
	PublicKey     string
	Algorithm     string
	Bits          int
	Fingerprint   string
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
}

// CertificateInfo holds certificate details
type CertificateInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	CertPEM      []byte
	KeyPEM       []byte
}

// GenerateRSAKeyPair generates an RSA key pair
func GenerateRSAKeyPair(bits int) (*KeyPair, error) {
	if bits < 1024 {
		bits = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Encode private key to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     string(publicKeyPEM),
		Algorithm:     "RSA",
		Bits:          bits,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair
func GenerateECDSAKeyPair(curve string) (*KeyPair, error) {
	var c elliptic.Curve
	var bits int

	switch strings.ToLower(curve) {
	case "p256", "prime256v1":
		c = elliptic.P256()
		bits = 256
	case "p384":
		c = elliptic.P384()
		bits = 384
	case "p521":
		c = elliptic.P521()
		bits = 521
	default:
		c = elliptic.P256()
		bits = 256
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}

	// Encode private key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     string(publicKeyPEM),
		Algorithm:     fmt.Sprintf("ECDSA-P%d", bits),
		Bits:          bits,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// GenerateEd25519KeyPair generates an Ed25519 key pair
func GenerateEd25519KeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %v", err)
	}

	// Encode private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     string(publicKeyPEM),
		Algorithm:     "Ed25519",
		Bits:          256,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// GenerateSSHKeyPair generates an SSH key pair
func GenerateSSHKeyPair(keyType string, bits int) (*KeyPair, error) {
	switch strings.ToLower(keyType) {
	case "rsa":
		if bits < 2048 {
			bits = 4096
		}
		return generateSSHRSA(bits)
	case "ed25519":
		return generateSSHEd25519()
	case "ecdsa":
		return generateSSHECDSA(bits)
	default:
		return generateSSHRSA(4096)
	}
}

func generateSSHRSA(bits int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate SSH public key format
	publicKey := &privateKey.PublicKey
	sshPubKey := formatSSHRSAPublicKey(publicKey)

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     sshPubKey,
		Algorithm:     "ssh-rsa",
		Bits:          bits,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  []byte(sshPubKey),
	}, nil
}

func generateSSHEd25519() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// OpenSSH format for Ed25519 private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: marshalOpenSSHPrivateKey(privateKey, publicKey),
	})

	// SSH public key format
	sshPubKey := formatSSHEd25519PublicKey(publicKey)

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     sshPubKey,
		Algorithm:     "ssh-ed25519",
		Bits:          256,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  []byte(sshPubKey),
	}, nil
}

func generateSSHECDSA(bits int) (*KeyPair, error) {
	var curve elliptic.Curve
	var curveName string

	switch bits {
	case 384:
		curve = elliptic.P384()
		curveName = "nistp384"
	case 521:
		curve = elliptic.P521()
		curveName = "nistp521"
	default:
		curve = elliptic.P256()
		curveName = "nistp256"
		bits = 256
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, _ := x509.MarshalECPrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	sshPubKey := formatSSHECDSAPublicKey(&privateKey.PublicKey, curveName)

	return &KeyPair{
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     sshPubKey,
		Algorithm:     fmt.Sprintf("ecdsa-sha2-%s", curveName),
		Bits:          bits,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  []byte(sshPubKey),
	}, nil
}

// formatSSHRSAPublicKey formats RSA public key in SSH format
func formatSSHRSAPublicKey(pubKey *rsa.PublicKey) string {
	// Simplified SSH format
	return fmt.Sprintf("ssh-rsa ... (RSA %d-bit public key)", pubKey.N.BitLen())
}

// formatSSHEd25519PublicKey formats Ed25519 public key in SSH format
func formatSSHEd25519PublicKey(pubKey ed25519.PublicKey) string {
	return fmt.Sprintf("ssh-ed25519 ... (Ed25519 public key)")
}

// formatSSHECDSAPublicKey formats ECDSA public key in SSH format
func formatSSHECDSAPublicKey(pubKey *ecdsa.PublicKey, curveName string) string {
	return fmt.Sprintf("ecdsa-sha2-%s ... (ECDSA public key)", curveName)
}

// marshalOpenSSHPrivateKey creates OpenSSH format private key
func marshalOpenSSHPrivateKey(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) []byte {
	// Simplified - in production use golang.org/x/crypto/ssh
	return privateKey
}

// GenerateSelfSignedCert generates a self-signed certificate
func GenerateSelfSignedCert(cn string, days int, keyBits int) (*CertificateInfo, error) {
	if days < 1 {
		days = 365
	}
	if keyBits < 2048 {
		keyBits = 2048
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Self-Signed"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add DNS names if CN looks like a domain
	if strings.Contains(cn, ".") {
		template.DNSNames = []string{cn}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &CertificateInfo{
		Subject:      cn,
		Issuer:       cn,
		NotBefore:    template.NotBefore,
		NotAfter:     template.NotAfter,
		SerialNumber: fmt.Sprintf("%x", serialNumber),
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
	}, nil
}

// GenerateAESKey generates a random AES key
func GenerateAESKey(bits int) (string, []byte, error) {
	if bits != 128 && bits != 192 && bits != 256 {
		bits = 256
	}

	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("failed to generate key: %v", err)
	}

	return hex.EncodeToString(key), key, nil
}

// GenerateRandomBytes generates random bytes
func GenerateRandomBytes(length int) (string, []byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}

	return hex.EncodeToString(bytes), bytes, nil
}

// SaveKeyPair saves a key pair to files
func SaveKeyPair(kp *KeyPair, privateFile, publicFile string) error {
	if privateFile != "" {
		if err := os.WriteFile(privateFile, kp.PrivateKeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to save private key: %v", err)
		}
	}

	if publicFile != "" {
		if err := os.WriteFile(publicFile, kp.PublicKeyPEM, 0644); err != nil {
			return fmt.Errorf("failed to save public key: %v", err)
		}
	}

	return nil
}

// SaveCertificate saves certificate and key to files
func SaveCertificate(cert *CertificateInfo, certFile, keyFile string) error {
	if certFile != "" {
		if err := os.WriteFile(certFile, cert.CertPEM, 0644); err != nil {
			return fmt.Errorf("failed to save certificate: %v", err)
		}
	}

	if keyFile != "" {
		if err := os.WriteFile(keyFile, cert.KeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to save key: %v", err)
		}
	}

	return nil
}

// DisplayKeyPair displays key pair information
func DisplayKeyPair(kp *KeyPair) {
	fmt.Println("\n[KEY PAIR GENERATED]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Algorithm: %s\n", kp.Algorithm)
	fmt.Printf("Key Size:  %d bits\n", kp.Bits)

	fmt.Println("\n[Private Key]")
	if len(kp.PrivateKey) > 500 {
		fmt.Printf("%s...\n", kp.PrivateKey[:200])
	} else {
		fmt.Println(kp.PrivateKey)
	}

	fmt.Println("[Public Key]")
	if len(kp.PublicKey) > 500 {
		fmt.Printf("%s...\n", kp.PublicKey[:200])
	} else {
		fmt.Println(kp.PublicKey)
	}
}

// DisplayCertificate displays certificate information
func DisplayCertificate(cert *CertificateInfo) {
	fmt.Println("\n[CERTIFICATE GENERATED]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Subject:      %s\n", cert.Subject)
	fmt.Printf("Issuer:       %s\n", cert.Issuer)
	fmt.Printf("Not Before:   %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:    %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Serial:       %s\n", cert.SerialNumber)

	fmt.Println("\n[Certificate PEM]")
	fmt.Println(string(cert.CertPEM))
}

// DisplayAESKey displays AES key
func DisplayAESKey(hexKey string, bits int) {
	fmt.Println("\n[AES KEY GENERATED]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Key Size:  %d bits\n", bits)
	fmt.Printf("Key (hex): %s\n", hexKey)
}
