package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"reflect"

	"golang.org/x/crypto/nacl/secretbox"
)

// Encrypt all tagged fields to their targets.
func (e *Transform) Encrypt(input interface{}) error {
	value, valueType, err := validateInput(input)
	if err != nil {
		return err
	}

	for i := 0; i < valueType.NumField(); i++ {
		sourceTypeField := valueType.Field(i)

		tagValue, ok := sourceTypeField.Tag.Lookup(encryptTag)
		if ok {

			targetName, clearSource := parseTagValue(tagValue)

			sourceField := value.Field(i)
			targetField := value.FieldByName(targetName)

			if !targetField.IsValid() {
				return FieldError{"target", targetName, "not valid"}
			}

			if !targetField.CanSet() {
				return FieldError{"target", targetName, "can not be set"}
			}

			var nonce [24]byte
			if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
				return FieldError{"source", sourceTypeField.Name, fmt.Sprintf("unable to create nonce: %v", err)}
			}

			var encrypted []byte

			// encrypt source
			switch getFieldType(sourceField) {
			case fieldTypeString:
				encrypted = secretbox.Seal(nonce[:],
					[]byte(sourceField.String()),
					&nonce,
					&e.secret)
			case fieldTypeByteSlice:
				encrypted = secretbox.Seal(nonce[:],
					sourceField.Bytes(),
					&nonce,
					&e.secret)
			case fieldTypeUnsupported:
				return FieldError{"source", sourceTypeField.Name, "must be a string or []byte"}
			}

			// set target
			switch getFieldType(targetField) {
			case fieldTypeString:
				targetField.SetString(base64.StdEncoding.EncodeToString(encrypted))
			case fieldTypeByteSlice:
				targetField.Set(reflect.ValueOf(encrypted))
			case fieldTypeUnsupported:
				return FieldError{"target", targetName, "must be a string or []byte"}
			}

			// clear source
			if clearSource {
				if sourceField.CanSet() {
					switch getFieldType(sourceField) {
					case fieldTypeString:
						sourceField.SetString("")
					case fieldTypeByteSlice:
						sourceField.Set(reflect.ValueOf([]byte{}))
					case fieldTypeUnsupported:
						return FieldError{"source", sourceTypeField.Name, "must be a string or []byte"}
					}
				} else {
					return FieldError{"source", sourceTypeField.Name, "can not be cleared"}
				}
			}
		}
	}

	return nil
}
