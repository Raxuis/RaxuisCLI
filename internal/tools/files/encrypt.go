package files

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

type EncryptOptions struct {
	Algorithm  string
	Password   string
	KeyFile    string
	OutputPath string
	Overwrite  bool
	Armor      bool
	Salt       bool
}

type DecryptOptions struct {
	Algorithm  string
	Password   string
	KeyFile    string
	OutputPath string
	Overwrite  bool
}

// Encrypt chiffre un fichier avec l'algorithme spécifié
func Encrypt(inputPath string, opts EncryptOptions) error {
	// Lire le fichier d'entrée
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	var ciphertext []byte
	switch opts.Algorithm {
	case "aes256":
		ciphertext, err = encryptAES256(plaintext, opts.Password, opts.Salt)
	case "chacha20":
		ciphertext, err = encryptChaCha20(plaintext, opts.Password, opts.Salt)
	case "rsa":
		ciphertext, err = encryptRSA(plaintext, opts.KeyFile)
	default:
		return fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}

	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Déterminer le chemin de sortie
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = inputPath + ".enc"
	}

	// Vérifier si le fichier existe
	if !opts.Overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file already exists: %s", outputPath)
		}
	}

	// Écrire le fichier chiffré
	if err := os.WriteFile(outputPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("error writing encrypted file: %w", err)
	}

	fmt.Printf("File encrypted successfully: %s\n", outputPath)
	return nil
}

// Decrypt déchiffre un fichier
func Decrypt(inputPath string, opts DecryptOptions) error {
	// Lire le fichier chiffré
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %w", err)
	}

	var plaintext []byte
	switch opts.Algorithm {
	case "aes256":
		plaintext, err = decryptAES256(ciphertext, opts.Password)
	case "chacha20":
		plaintext, err = decryptChaCha20(ciphertext, opts.Password)
	case "rsa":
		plaintext, err = decryptRSA(ciphertext, opts.KeyFile)
	default:
		return fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}

	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Déterminer le chemin de sortie
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = inputPath + ".dec"
	}

	// Vérifier si le fichier existe
	if !opts.Overwrite {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("output file already exists: %s", outputPath)
		}
	}

	// Écrire le fichier déchiffré
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("error writing decrypted file: %w", err)
	}

	fmt.Printf("File decrypted successfully: %s\n", outputPath)
	return nil
}

// encryptAES256 chiffre avec AES-256-GCM
func encryptAES256(plaintext []byte, password string, useSalt bool) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required for AES encryption")
	}

	// Générer le sel si nécessaire
	var salt []byte
	if useSalt {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	} else {
		salt = make([]byte, 32)
	}

	// Dériver la clé avec PBKDF2
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Créer le cipher AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Utiliser GCM pour l'authentification
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Générer le nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Chiffrer
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Format: salt (32) + ciphertext (nonce inclus)
	result := append(salt, ciphertext...)
	return result, nil
}

// decryptAES256 déchiffre avec AES-256-GCM
func decryptAES256(data []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required for AES decryption")
	}

	if len(data) < 32 {
		return nil, errors.New("invalid encrypted data")
	}

	// Extraire le sel
	salt := data[:32]
	ciphertext := data[32:]

	// Dériver la clé
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Créer le cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	// Extraire le nonce et déchiffrer
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptChaCha20 chiffre avec ChaCha20-Poly1305
func encryptChaCha20(plaintext []byte, password string, useSalt bool) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required for ChaCha20 encryption")
	}

	// Générer le sel
	var salt []byte
	if useSalt {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	} else {
		salt = make([]byte, 32)
	}

	// Dériver la clé
	key := pbkdf2.Key([]byte(password), salt, 100000, chacha20poly1305.KeySize, sha256.New)

	// Créer le cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Générer le nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Chiffrer
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	// Format: salt + ciphertext
	result := append(salt, ciphertext...)
	return result, nil
}

// decryptChaCha20 déchiffre avec ChaCha20-Poly1305
func decryptChaCha20(data []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required for ChaCha20 decryption")
	}

	if len(data) < 32 {
		return nil, errors.New("invalid encrypted data")
	}

	// Extraire le sel
	salt := data[:32]
	ciphertext := data[32:]

	// Dériver la clé
	key := pbkdf2.Key([]byte(password), salt, 100000, chacha20poly1305.KeySize, sha256.New)

	// Créer le cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}

	// Extraire le nonce et déchiffrer
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// encryptRSA chiffre avec RSA
func encryptRSA(plaintext []byte, keyFile string) ([]byte, error) {
	if keyFile == "" {
		return nil, errors.New("key file is required for RSA encryption")
	}

	// Lire la clé publique
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	// Chiffrer avec RSA-OAEP
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// decryptRSA déchiffre avec RSA
func decryptRSA(ciphertext []byte, keyFile string) ([]byte, error) {
	if keyFile == "" {
		return nil, errors.New("key file is required for RSA decryption")
	}

	// Lire la clé privée
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Essayer PKCS1
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Déchiffrer
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
