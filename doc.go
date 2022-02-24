/*
Package crypt implements a transformer which encrypts and decrypts struct fields based on their tags.
The struct tags determine which fields are plaintext, and which are ciphertext.

The tag for a plaintext field is "encrypt" followed by a target field name to place the ciphertext into, e.g.
	`encrypt:"Ciphertext"`

The tag for a ciphertext field is "decrypt" followed by a target field name to place the plaintext into, e.g.
	`decrypt:"Plaintext"`

The tags are not required to be symmetric, so you do not have to decrypt into the same field that encrypts into another field.

All fields must be a byte slice, or a string. If the ciphertext field is a string, it will be stored as a base64 representation of the underlying bytes.

By default, all fields are cleared to their zero value after they are transformed.  If you do not want this behavior on a field, you may add `,preserve` to the tag, e.g. `encrypt:"password,preserve"`

All encryption is done though the golang.org/x/crypto/nacl/secretbox package.
*/
package crypt
