package crypt

import "testing"

var testSecret [32]byte = [32]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
}

func Test_SmokeTest(t *testing.T) {
	transform := New(testSecret)

	type example struct {
		Plaintext  string `encrypt:"Ciphertext"`
		Ciphertext string `decrypt:"Plaintext"`
	}

	plaintext := "top secret"

	e := example{Plaintext: plaintext}

	err := transform.Encrypt(&e)
	if err != nil {
		t.Fatalf("error encrypting: %v", err)
	}

	if e.Plaintext != "" {
		t.Error("plaintext not cleared")
	}
	if e.Ciphertext == "" {
		t.Error("ciphertext not set")
	}

	err = transform.Decrypt(&e)
	if err != nil {
		t.Fatalf("error decrypting: %v", err)
	}

	if e.Plaintext != plaintext {
		t.Errorf("plaintext not set\nexpected: %q\n  actual: %v", plaintext, e.Plaintext)
	}
	if e.Ciphertext != "" {
		t.Errorf("ciphertext not cleared")
	}
}
