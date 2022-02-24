package crypt

import (
	"encoding/base64"
	"reflect"

	"golang.org/x/crypto/nacl/secretbox"
)

// Decrypt all tagged fields to their targets.
func (e *Transform) Decrypt(input interface{}) error {
	value, valueType, err := validateInput(input)
	if err != nil {
		return err
	}

	for i := 0; i < valueType.NumField(); i++ {
		sourceTypeField := valueType.Field(i)

		tagValue, ok := sourceTypeField.Tag.Lookup(decryptTag)
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

			var (
				nonce   [24]byte
				message []byte
			)

			// encrypt source
			switch getFieldType(sourceField) {
			case fieldTypeString:
				message, err = base64.StdEncoding.DecodeString(sourceField.String())
				if err != nil {
					return FieldError{"source", sourceTypeField.Name, err.Error()}
				}
			case fieldTypeByteSlice:
				message = sourceField.Bytes()
			case fieldTypeUnsupported:
				return FieldError{"source", sourceTypeField.Name, "must be a string or []byte"}
			}

			copy(nonce[:], message[:24])
			decrypted, ok := secretbox.Open(nil, message[24:], &nonce, &e.secret)
			if !ok {
				return FieldError{"source", sourceTypeField.Name, "unable to decrypt"}
			}

			// set target
			switch getFieldType(targetField) {
			case fieldTypeString:
				targetField.SetString(string(decrypted))
			case fieldTypeByteSlice:
				targetField.Set(reflect.ValueOf(decrypted))
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
						return FieldError{"source", targetName, "must be a string or []byte"}
					}
				} else {
					return FieldError{"source", sourceTypeField.Name, "can not be set"}
				}
			}
		}
	}

	return nil
}
