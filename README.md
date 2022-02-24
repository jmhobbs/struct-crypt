[![Build Status](https://travis-ci.org/jmhobbs/struct-crypt.svg?branch=main)](https://travis-ci.org/jmhobbs/struct-crypt) [![codecov](https://codecov.io/gh/jmhobbs/struct-crypt/branch/main/graph/badge.svg)](https://codecov.io/gh/jmhobbs/struct-crypt) [![PkgGoDev](https://pkg.go.dev/badge/github.com/jmhobbs/struct-crypt)](https://pkg.go.dev/github.com/jmhobbs/struct-crypt)

# struct-crypt

This package provides simple struct tag based encryption for Go via the [nacl/secretbox](golang.org/x/crypto/nacl/secretbox) api.

The package provides a `Transform` struct which holds your secret key.  This can then be applied to `Encrypt` a struct, or `Decrypt` a struct.

The struct tags determine which fields are plaintext, and which are ciphertext.

The tag for a plaintext field is "encrypt" followed by a target field name to place the ciphertext into, e.g. `encrypt:"CiphertextTarget"`

The tag for a ciphertext field is "decrypt" followed by a target field name to place the plaintext into, e.g. `decrypt:"PlaintextTarget"`

The tags are not required to be symmetric, so you do not have to decrypt into the same field that encrypts into another field.

All fields must be a byte slice, or a string. If the ciphertext field is a string, it will be stored as a base64 standard encoding representation of the underlying bytes.

By default, all fields are cleared to their zero value after they are transformed.  If you do not want this behavior on a field, you may add `,preserve` to the tag, e.g. `encrypt:"password,preserve"`

## Example

```go
package main

import (
	crypt "github.com/jmhobbs/struct-crypt"
)

type example struct {
	Plaintext  string `encrypt:"Ciphertext"`
	Ciphertext string `decrypt:"Plaintext"`
	DecSecret  string `encrypt:"EncSecret,preserve"`
	EncSecret  []byte `decrypt:"DecSecret,preserve"`
}

func main() {
	var secret [32]byte
	copy(secret[:], []byte("-----32-byte-encryption-key-----"))

	transform := crypt.New(secret)

	e := example{
		Plaintext: "top secret",
		DecSecret: "also secret",
	}
	/*
	 Plaintext: "top secret"
	Ciphertext: ""
	 DecSecret: "also secret"
	 EncSecret: []
	*/

	err := transform.Encrypt(&e)
	if err != nil {
		panic(err)
	}
	/*
	 Plaintext: ""
	Ciphertext: "dmvKi8BR0ehuM3Eu6zuZZeqEjAB6hbGom+FWAsWSFSehSqpvgU0cEK44M4Bv6Mo6gjo="
	 DecSecret: "also secret"
	 EncSecret: [39 142 155 38 15...119 35 109]
	*/

	err = transform.Decrypt(&e)
	/*
	 Plaintext: "top secret"
	Ciphertext: ""
	 DecSecret: "also secret"
	 EncSecret: [39 142 155 38 15...119 35 109]
	*/
}
```