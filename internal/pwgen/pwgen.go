package pwgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Options struct {
	Length    int
	NoSymbols bool
	NoNumbers bool
}

const (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers = "0123456789"
	symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

func Generate(opts Options) (string, error) {
	charset := letters

	if !opts.NoNumbers {
		charset += numbers
	}

	if !opts.NoSymbols {
		charset += symbols
	}

	password := make([]byte, opts.Length)

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("error generating random number: %w", err)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}
