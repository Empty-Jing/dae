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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestMergeEncryptedConfig(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "dae.key")
	plainPath := filepath.Join(tmpDir, "config.dae")
	passphrase := []byte("test-secret\n")
	plain := []byte("global {\n    tproxy_port: 12345\n}\nrouting {\n    fallback: direct\n}\n")
	if err := os.WriteFile(keyPath, passphrase, 0600); err != nil {
		t.Fatal(err)
	}
	payload := mustEncryptOpenSSLBase64(t, plain, bytes.TrimSpace(passphrase), []byte("12345678"), defaultOpenSSLIter)
	if err := os.WriteFile(plainPath, []byte(payload+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err := NewMerger(plainPath, "file:"+keyPath).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.TproxyPort != 12345 {
		t.Fatalf("unexpected tproxy_port: %d", conf.Global.TproxyPort)
	}
}

func TestMergeEncryptedConfigUsesFirstLineOfKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "dae.key")
	configPath := filepath.Join(tmpDir, "config.dae")
	plain := []byte("global {\n    tproxy_port: 12345\n}\nrouting {\n    fallback: direct\n}\n")
	if err := os.WriteFile(keyPath, []byte("test-secret\nignored-line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := mustEncryptOpenSSLBase64(t, plain, []byte("test-secret"), []byte("12345678"), defaultOpenSSLIter)
	if err := os.WriteFile(configPath, []byte(payload+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err := NewMerger(configPath, "file:"+keyPath).Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.TproxyPort != 12345 {
		t.Fatalf("unexpected tproxy_port: %d", conf.Global.TproxyPort)
	}
}

func TestMergeEncryptedConfigBadKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "dae.key")
	configPath := filepath.Join(tmpDir, "config.dae")
	if err := os.WriteFile(keyPath, []byte("wrong-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := mustEncryptOpenSSLBase64(t, []byte("global{}\nrouting{fallback:direct}\n"), []byte("right-key"), []byte("12345678"), defaultOpenSSLIter)
	if err := os.WriteFile(configPath, []byte(payload+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := NewMerger(configPath, "file:"+keyPath).Merge()
	if err == nil {
		t.Fatal("expected decryption failure")
	}
	if !strings.Contains(err.Error(), "failed to decrypt config file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMergePlainConfigUnaffected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.dae")
	content := "global {\n    tproxy_port: 23456\n}\nrouting {\n    fallback: direct\n}\n"
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	sections, _, err := NewMerger(configPath, "").Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.TproxyPort != 23456 {
		t.Fatalf("unexpected tproxy_port: %d", conf.Global.TproxyPort)
	}
}

func TestEncryptedConfigWithoutConfigKeyFailsParsing(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "dae.key")
	configPath := filepath.Join(tmpDir, "config.dae")
	if err := os.WriteFile(keyPath, []byte("test-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := mustEncryptOpenSSLBase64(t, []byte("global{}\nrouting{fallback:direct}\n"), []byte("test-secret"), []byte("12345678"), defaultOpenSSLIter)
	if err := os.WriteFile(configPath, []byte(payload+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := NewMerger(configPath, "").Merge()
	if err == nil {
		t.Fatal("expected parse failure without config key")
	}
}

func mustEncryptOpenSSLBase64(t *testing.T, plaintext []byte, passphrase []byte, salt []byte, iter int) string {
	t.Helper()
	if len(salt) != openSSLSaltLen {
		t.Fatalf("unexpected salt length: %d", len(salt))
	}
	derived := pbkdf2.Key(passphrase, salt, iter, aes256KeyLen+aesBlockLen, sha256.New)
	block, err := aes.NewCipher(derived[:aes256KeyLen])
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plaintext, aesBlockLen)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, derived[aes256KeyLen:]).CryptBlocks(ciphertext, padded)
	buf := append([]byte(openSSLHeader), salt...)
	buf = append(buf, ciphertext...)
	return base64.StdEncoding.EncodeToString(buf)
}

func pkcs7Pad(plaintext []byte, blockSize int) []byte {
	paddingLen := blockSize - len(plaintext)%blockSize
	return append(plaintext, bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)...)
}
