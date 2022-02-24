package crypt

import "crypto/rand"


func Example() {
	// Struct tags target other, public fields, and do not have to be symmetric.
	type ExampleStruct struct {
		StringPlainText  string `encrypt:"BytesCipherText"`
		StringCipherText string `decrypt:"StringPlainText"`
		BytesPlainText   []byte `encrypt:"StringCipherText"`
		BytesCipherText  []byte `decrypt:"BytesPlainText"`
	}

	// By default fields are cleared when encrypted or decrypted. Use `,preserve` to prevent this.
	type PreserveStruct struct {
		PlainText  string `encrypt:"CipherText,preserve"`
		CipherText string `decrypt:"PlainText"`
	}
}

// Ensure you use a strong random source to generate your key, and keep it safe.
func ExampleNew() {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err.Error())
	}
	var secret [32]byte
	copy(secret[:], buf[:])
	_ = New(secret)
}
