package crypt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func Test_Decrypt(t *testing.T) {
	crypt := Transform{testSecret}

	plaintext := "top secret bytes"
	plainTextBytes := []byte(plaintext)

	ciphertext := "Y7KKFThVuVppQZKb0a5pJGA6Tx1VlVFldrKOBZQeGMAenqE4f25i/M8HmX0n3J7qfCx1cqcCiR0="
	cipherTextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatalf("unable to decode sample ciphertext: %v", err)
	}

	t.Run("string to slice", func(t *testing.T) {
		obj := struct {
			PlainText  []byte
			CipherText string `decrypt:"PlainText"`
		}{
			CipherText: ciphertext,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if !bytes.Equal(plainTextBytes, obj.PlainText) {
			t.Errorf("plaintext incorrect\nexpected: %v\n  actual: %v", plainTextBytes, obj.PlainText)
		}
	})

	t.Run("string to string", func(t *testing.T) {
		obj := struct {
			PlainText  string
			CipherText string `decrypt:"PlainText"`
		}{
			CipherText: ciphertext,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if plaintext != obj.PlainText {
			t.Errorf("plaintext incorrect\nexpected: %v\n  actual: %v", plaintext, obj.PlainText)
		}
	})

	t.Run("slice to slice", func(t *testing.T) {
		obj := struct {
			PlainText  []byte
			CipherText []byte `decrypt:"PlainText"`
		}{
			CipherText: cipherTextBytes,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if !bytes.Equal(plainTextBytes, obj.PlainText) {
			t.Errorf("plaintext incorrect\nexpected: %v\n  actual: %v", plainTextBytes, obj.PlainText)
		}
	})

	t.Run("slice to string", func(t *testing.T) {
		obj := struct {
			PlainText  string
			CipherText []byte `decrypt:"PlainText"`
		}{
			CipherText: cipherTextBytes,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if plaintext != obj.PlainText {
			t.Errorf("plaintext incorrect\nexpected: %v\n  actual: %v", plaintext, obj.PlainText)
		}
	})

	t.Run("preserve source", func(t *testing.T) {
		obj := struct {
			PlainText  string
			CipherText string `decrypt:"PlainText,preserve"`
		}{
			CipherText: ciphertext,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if obj.CipherText != ciphertext {
			t.Errorf("ciphertext not preserved\nexpected: %q\n  actual: %q", ciphertext, obj.CipherText)
		}
	})

	t.Run("clear source", func(t *testing.T) {
		obj := struct {
			PlainText  string
			CipherText string `decrypt:"PlainText"`
		}{
			CipherText: ciphertext,
		}

		if err := crypt.Decrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		if obj.CipherText != "" {
			t.Errorf("ciphertext not cleared\nexpected: %q\n  actual: %q", "", obj.CipherText)
		}
	})

}
