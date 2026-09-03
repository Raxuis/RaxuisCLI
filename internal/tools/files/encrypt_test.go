package files

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptAES256RoundTrip(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "top secret content")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "aes256", Password: "correct horse", Salt: true}); err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	encPath := inputPath + ".enc"
	decPath := filepath.Join(dir, "out.dec")
	if err := Decrypt(encPath, DecryptOptions{Algorithm: "aes256", Password: "correct horse", OutputPath: decPath}); err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}
	if string(got) != "top secret content" {
		t.Errorf("decrypted content = %q, want %q", got, "top secret content")
	}
}

func TestEncryptDecryptChaCha20RoundTrip(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "chacha secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "chacha20", Password: "hunter2", Salt: true}); err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	encPath := inputPath + ".enc"
	decPath := filepath.Join(dir, "out.dec")
	if err := Decrypt(encPath, DecryptOptions{Algorithm: "chacha20", Password: "hunter2", OutputPath: decPath}); err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}
	if string(got) != "chacha secret" {
		t.Errorf("decrypted content = %q, want %q", got, "chacha secret")
	}
}

func genRSAKeyPair(t *testing.T, dir string) (pubPath, privPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPath = filepath.Join(dir, "pub.pem")
	pubFile, _ := os.Create(pubPath)
	pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	pubFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPath = filepath.Join(dir, "priv.pem")
	privFile, _ := os.Create(privPath)
	pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	privFile.Close()

	return pubPath, privPath
}

func TestEncryptDecryptRSARoundTrip(t *testing.T) {
	dir := t.TempDir()
	pubPath, privPath := genRSAKeyPair(t, dir)
	inputPath := writeFile(t, dir, "plain.txt", "rsa secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "rsa", KeyFile: pubPath}); err != nil {
		t.Fatalf("Encrypt(rsa) returned error: %v", err)
	}

	encPath := inputPath + ".enc"
	decPath := filepath.Join(dir, "out.dec")
	if err := Decrypt(encPath, DecryptOptions{Algorithm: "rsa", KeyFile: privPath, OutputPath: decPath}); err != nil {
		t.Fatalf("Decrypt(rsa) returned error: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}
	if string(got) != "rsa secret" {
		t.Errorf("decrypted content = %q, want %q", got, "rsa secret")
	}
}

func TestEncryptWrongPasswordFailsDecrypt(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "aes256", Password: "right"}); err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	err := Decrypt(inputPath+".enc", DecryptOptions{Algorithm: "aes256", Password: "wrong", OutputPath: filepath.Join(dir, "out.dec")})
	if err == nil {
		t.Error("Decrypt with the wrong password should return an error")
	}
}

func TestEncryptUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "bogus"}); err == nil {
		t.Error("Encrypt with an unsupported algorithm should return an error")
	}
}

func TestDecryptUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "cipher.enc", "not real ciphertext")

	if err := Decrypt(inputPath, DecryptOptions{Algorithm: "bogus"}); err == nil {
		t.Error("Decrypt with an unsupported algorithm should return an error")
	}
}

func TestEncryptMissingInputFile(t *testing.T) {
	if err := Encrypt("/nonexistent/file", EncryptOptions{Algorithm: "aes256", Password: "x"}); err == nil {
		t.Error("Encrypt on a missing input file should return an error")
	}
}

func TestEncryptRefusesToOverwriteWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "secret")
	writeFile(t, dir, "plain.txt.enc", "existing content")

	err := Encrypt(inputPath, EncryptOptions{Algorithm: "aes256", Password: "x"})
	if err == nil {
		t.Error("Encrypt should refuse to overwrite an existing output file without Overwrite=true")
	}
}

func TestEncryptAESMissingPassword(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "aes256"}); err == nil {
		t.Error("Encrypt(aes256) with no password should return an error")
	}
}

func TestEncryptRSAMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := writeFile(t, dir, "plain.txt", "secret")

	if err := Encrypt(inputPath, EncryptOptions{Algorithm: "rsa"}); err == nil {
		t.Error("Encrypt(rsa) with no key file should return an error")
	}
}
