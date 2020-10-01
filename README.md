[![Build Status](https://travis-ci.org/jmhobbs/struct-crypt.svg?branch=master)](https://travis-ci.org/jmhobbs/struct-crypt) [![codecov](https://codecov.io/gh/jmhobbs/struct-crypt/branch/master/graph/badge.svg)](https://codecov.io/gh/jmhobbs/struct-crypt) [![PkgGoDev](https://pkg.go.dev/badge/github.com/jmhobbs/struct-crypt)](https://pkg.go.dev/github.com/jmhobbs/struct-crypt)

# struct-crypt

This package provides simple struct tag based encryption for Go via the [nacl/secretbox](golang.org/x/crypto/nacl/secretbox) api.

The package provides a `Transform` struct which holds your secret key.  This can then be applied to `Encrypt` a struct, or `Decrypt` a struct.

The struct tags determine which fields are plaintext, and which are ciphertext.

The tag for a plaintext field is "encrypt" followed by a target field name to place the ciphertext into, e.g. `encrypt:"CiphertextTarget"`

The tag for a ciphertext field is "decrypt" followed by a target field name to place the plaintext into, e.g. `decrypt:"PlaintextTarget"`

The tags are not required to be symmetric, so you do not have to decrypt into the same field that encrypts into another field.

All fields must be a byte slice, or a string. If the ciphertext field is a string, it will be stored as a base64 standard encoding representation of the underlying bytes.

By default, all fields are cleared to their zero value after they are transformed.  If you do not want this behavior on a field, you may add `,preserve` to the tag, e.g. `encrypt:"password,preserve"`
