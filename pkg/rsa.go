package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const (
	pubKeyBeginArmor  = "-----BEGIN RSA PUBLIC KEY-----"
	pubKeyEndArmor    = "-----END RSA PUBLIC KEY-----"
	privKeyBeginArmor = "-----BEGIN RSA PRIVATE KEY-----"
	privKeyEndArmor   = "-----END RSA PRIVATE KEY-----"
)

func ReadPublicKeyFromPEMFile(filepath string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key from file: %w", err)
	}
	return ReadPublicKeyFromPEM(b)
}

func ReadPublicKeyFromPEM(pemContents []byte) (*rsa.PublicKey, error) {
	for block, rest := pem.Decode(pemContents); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "RSA PUBLIC KEY" {
			return x509.ParsePKCS1PublicKey(block.Bytes)
		}
	}
	return nil, fmt.Errorf("public key not found in pem contents")
}

func FormatPublicKeyForPEMFile(publicKey *rsa.PublicKey) (string, error) {
	if publicKey == nil {
		return "", fmt.Errorf("public key cannot be nil")
	}
	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pemBytes), nil
}

func ReadPublicKeyFromPEMEnvVar(envVarValue string) (*rsa.PublicKey, error) {
	stripped := strings.ReplaceAll(envVarValue, pubKeyBeginArmor, "")
	stripped = strings.ReplaceAll(stripped, pubKeyEndArmor, "")
	newlines := strings.ReplaceAll(stripped, " ", "\n")
	return ReadPublicKeyFromPEM([]byte(fmt.Sprintf("%s%s%s", pubKeyBeginArmor, newlines, pubKeyEndArmor)))
}

func FormatPublicKeyForPEMEnvVar(publicKey *rsa.PublicKey) (string, error) {
	s, err := FormatPublicKeyForPEMFile(publicKey)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(s, "\n", " "), nil
}

func ReadPrivateKeyFromPEMFile(filepath string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key from file: %w", err)
	}
	return ReadPrivateKeyFromPEM(b)
}

func ReadPrivateKeyFromPEM(pemContents []byte) (*rsa.PrivateKey, error) {
	for block, rest := pem.Decode(pemContents); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "RSA PRIVATE KEY" {
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		}
	}
	return nil, fmt.Errorf("private key not found in pem")
}

func FormatPrivateKeyForPEMFile(privateKey *rsa.PrivateKey) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key cannot be nil")
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(pemBytes), nil
}

func ReadPrivateKeyFromPEMEnvVar(envVarValue string) (*rsa.PrivateKey, error) {
	stripped := strings.ReplaceAll(envVarValue, privKeyBeginArmor, "")
	stripped = strings.ReplaceAll(stripped, privKeyEndArmor, "")
	newlines := strings.ReplaceAll(stripped, " ", "\n")
	return ReadPrivateKeyFromPEM([]byte(fmt.Sprintf("%s%s%s", privKeyBeginArmor, newlines, privKeyEndArmor)))
}

func FormatPrivateKeyForPEMEnvVar(privateKey *rsa.PrivateKey) (string, error) {
	s, err := FormatPrivateKeyForPEMFile(privateKey)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(s, "\n", " "), nil
}
