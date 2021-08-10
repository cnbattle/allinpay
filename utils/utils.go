package utils

import (
	"crypto/sha1"
	"fmt"
)

// AesSha1PRNG aes_sha1_prng加密
func AesSha1PRNG(keyBytes []byte, encryptLength int) ([]byte, error) {
	hash := SHA1(SHA1(keyBytes))
	maxLen := len(hash)
	realLen := encryptLength / 8
	if realLen > maxLen {
		return nil, fmt.Errorf("Not Support %d, Only Support Lower then %d [% x]", realLen, maxLen, hash)
	}
	return hash[0:realLen], nil
}

// SHA1 SHA1加密
func SHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}
