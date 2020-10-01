package crypt

import "strings"

const (
	encryptTag string = "encrypt"
	decryptTag string = "decrypt"
)

// encrypt:"target,preserve"
// decrypt:"target"
func parseTagValue(tag string) (string, bool) {
	split := strings.Split(tag, ",")
	if len(split) == 2 && split[1] == "preserve" {
		return split[0], false
	}
	return tag, true
}
