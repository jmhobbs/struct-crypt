package crypt

import "reflect"

// Transform is used to automatically encrypt or decrypt fields.
type Transform struct {
	secret [32]byte
}

// New creates a Transform for the secret argument.
func New(secret [32]byte) *Transform {
	return &Transform{secret}
}

type fieldType uint8

const (
	fieldTypeUnsupported fieldType = 0
	fieldTypeString      fieldType = 1
	fieldTypeByteSlice   fieldType = 2
)

var byteSliceType = reflect.TypeOf([]byte{})

func getFieldType(field reflect.Value) fieldType {
	if field.Kind() == reflect.String {
		return fieldTypeString
	}
	if field.Kind() == reflect.Slice && field.Type() == byteSliceType {
		return fieldTypeByteSlice
	}
	return fieldTypeUnsupported
}

func validateInput(input interface{}) (reflect.Value, reflect.Type, error) {
	var (
		value     reflect.Value
		valueType reflect.Type
	)

	if reflect.TypeOf(input).Kind() != reflect.Ptr {
		return value, valueType, InvalidInputError{"input must be a struct pointer"}
	}

	ptrValue := reflect.ValueOf(input)
	if ptrValue.IsNil() {
		return value, valueType, InvalidInputError{"input can not be nil"}
	}

	value = ptrValue.Elem()
	valueType = value.Type()

	if valueType.Kind() != reflect.Struct {
		return value, valueType, InvalidInputError{"input must be a struct pointer"}
	}

	return value, valueType, nil
}
