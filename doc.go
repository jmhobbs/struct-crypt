/*
Package crypt implements a transformer which encrypts and decrypts struct fields based on their tags.
The struct tags determine which fields are plaintext, and which are ciphertext.

The tag for a plaintext field is "encrypt" followed by a target field name to place the ciphertext into, e.g.
	`encrypt:"Ciphertext"`

The tag for a ciphertext field is "decrypt" followed by a target field name to place the plaintext into, e.g.
	`decrypt:"Plaintext"`

The tags are not required to be symmetric, so you do not have to decrypt into the same field that encrypts into another field.

All fields must be a byte slice, or a string. If the ciphertext field is a string, it will be stored as a base64 representation of the underlying bytes.

All encryption is done though the golang.org/x/crypto/nacl/secretbox package.
*/
package crypt
