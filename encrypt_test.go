package crypt

import (
	"bytes"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

func Test_Encrypt(t *testing.T) {

	crypt := Transform{testSecret}

	t.Run("string to slice", func(t *testing.T) {
		plainText := "top secret string"

		obj := struct {
			PlainText  string `encrypt:"CipherText"`
			CipherText []byte
		}{
			PlainText: plainText,
		}

		if err := crypt.Encrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		var nonce [24]byte
		copy(nonce[:], obj.CipherText[:24])
		decrypted, ok := secretbox.Open(nil, obj.CipherText[24:], &nonce, &testSecret)
		if !ok {
			t.Errorf("unable to decrypt")
		}

		if string(decrypted) != plainText {
			t.Errorf("decrypted does not match plaintext\n%q != %q", string(decrypted), plainText)
		}
	})

	t.Run("string to string", func(t *testing.T) {
		plainText := "top secret string"

		obj := struct {
			PlainText  string `encrypt:"CipherText"`
			CipherText string
		}{
			PlainText: plainText,
		}

		if err := crypt.Encrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		cipherBytes, err := base64.StdEncoding.DecodeString(obj.CipherText)
		if err != nil {
			t.Fatalf("string not properly encoded: %v", err)
		}

		var nonce [24]byte
		copy(nonce[:], cipherBytes[:24])
		decrypted, ok := secretbox.Open(nil, cipherBytes[24:], &nonce, &testSecret)
		if !ok {
			t.Errorf("unable to decrypt")
		}

		if string(decrypted) != plainText {
			t.Errorf("decrypted does not match plaintext\n%q != %q", string(decrypted), plainText)
		}
	})

	t.Run("slice to slice", func(t *testing.T) {
		plaintext := []byte("top secret bytes")

		obj := struct {
			PlainText  []byte `encrypt:"CipherText"`
			CipherText []byte
		}{
			PlainText: plaintext,
		}

		if err := crypt.Encrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		var nonce [24]byte
		copy(nonce[:], obj.CipherText[:24])
		decrypted, ok := secretbox.Open(nil, obj.CipherText[24:], &nonce, &testSecret)
		if !ok {
			t.Errorf("unable to decrypt")
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted does not match plaintext\n%q != %q", string(decrypted), plaintext)
		}
	})

	t.Run("slice to string", func(t *testing.T) {
		plaintext := []byte("top secret bytes")
		obj := struct {
			PlainText  []byte `encrypt:"CipherText"`
			CipherText string
		}{
			PlainText: plaintext,
		}

		if err := crypt.Encrypt(&obj); err != nil {
			t.Fatalf("unable to encrypt: %v", err)
		}

		cipherBytes, err := base64.StdEncoding.DecodeString(obj.CipherText)
		if err != nil {
			t.Fatalf("string not properly encoded: %v", err)
		}

		var nonce [24]byte
		copy(nonce[:], cipherBytes[:24])
		decrypted, ok := secretbox.Open(nil, cipherBytes[24:], &nonce, &testSecret)
		if !ok {
			t.Errorf("unable to decrypt")
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted does not match plaintext\n%q != %q", string(decrypted), plaintext)
		}
	})
}
