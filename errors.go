package crypt

import "fmt"

type InvalidInputError struct {
	message string
}

func (err InvalidInputError) Error() string {
	return fmt.Sprintf("error: %s", err.message)
}

type FieldError struct {
	which   string
	field   string
	message string
}

func (err FieldError) Error() string {
	return fmt.Sprintf("error on %s field %q: %s", err.which, err.field, err.message)
}
