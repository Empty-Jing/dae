/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultOpenSSLIter          = 100000
	openSSLHeader               = "Salted__"
	openSSLSaltLen              = 8
	aes256KeyLen                = 32
	aesBlockLen                 = aes.BlockSize
)

func decryptConfigBytesIfNeeded(entry string, b []byte, configKey string) ([]byte, error) {
	if configKey == "" {
		return b, nil
	}
	keyFile, err := parseConfigKey(configKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse --config-key for %v: %w", entry, err)
	}
	if !filepath.IsAbs(keyFile) {
		keyFile = filepath.Join(filepath.Dir(entry), keyFile)
	}
	passphrase, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %v: %w", keyFile, err)
	}
	plaintext, err := decryptOpenSSLAES256CBCBase64(b, extractOpenSSLPassphrase(passphrase), defaultOpenSSLIter)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt config file %v: %w", entry, err)
	}
	return plaintext, nil
}

func extractOpenSSLPassphrase(passphrase []byte) []byte {
	if i := bytes.IndexByte(passphrase, '\n'); i >= 0 {
		passphrase = passphrase[:i]
	}
	return bytes.TrimRightFunc(passphrase, func(r rune) bool {
		return r == '\r'
	})
}

func parseConfigKey(configKey string) (string, error) {
	scheme, path, ok := strings.Cut(configKey, ":")
	if !ok || scheme == "" || path == "" {
		return "", fmt.Errorf("expect scheme:path, got %q", configKey)
	}
	switch scheme {
	case "file":
		if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") && len(path) > 2 && path[2] == ':' {
			path = path[1:]
		}
		return path, nil
	default:
		return "", fmt.Errorf("unsupported key scheme %q", scheme)
	}
}

func decryptOpenSSLAES256CBCBase64(payload []byte, passphrase []byte, iter int) ([]byte, error) {
	cleanPayload := removeASCIISpace(payload)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(cleanPayload)))
	n, err := base64.StdEncoding.Decode(decoded, cleanPayload)
	if err != nil {
		return nil, fmt.Errorf("base64 decode payload: %w", err)
	}
	decoded = decoded[:n]
	if len(decoded) < len(openSSLHeader)+openSSLSaltLen {
		return nil, errors.New("ciphertext is too short")
	}
	if string(decoded[:len(openSSLHeader)]) != openSSLHeader {
		return nil, errors.New("missing OpenSSL Salted__ header")
	}
	salt := decoded[len(openSSLHeader) : len(openSSLHeader)+openSSLSaltLen]
	ciphertext := decoded[len(openSSLHeader)+openSSLSaltLen:]
	if len(ciphertext) == 0 || len(ciphertext)%aesBlockLen != 0 {
		return nil, errors.New("ciphertext length is invalid")
	}
	derived := pbkdf2.Key(passphrase, salt, iter, aes256KeyLen+aesBlockLen, sha256.New)
	block, err := aes.NewCipher(derived[:aes256KeyLen])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, derived[aes256KeyLen:]).CryptBlocks(plaintext, ciphertext)
	plaintext, err = pkcs7Unpad(plaintext, aesBlockLen)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func removeASCIISpace(b []byte) []byte {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			clean = append(clean, c)
		}
	}
	return clean
}

func pkcs7Unpad(plaintext []byte, blockSize int) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, errors.New("invalid padded plaintext length")
	}
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen == 0 || paddingLen > blockSize || paddingLen > len(plaintext) {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for _, b := range plaintext[len(plaintext)-paddingLen:] {
		if int(b) != paddingLen {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return plaintext[:len(plaintext)-paddingLen], nil
}
