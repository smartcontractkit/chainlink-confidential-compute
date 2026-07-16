package util

import "encoding/base64"

func EncodeToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeString(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}
