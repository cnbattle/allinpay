package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"fmt"
)

// AESSHA1PRNG SHA1PRNG
func AESSHA1PRNG(keyBytes []byte, encryptLength int) ([]byte, error) {
	hashs := SHA1(SHA1(keyBytes))
	maxLen := len(hashs)
	realLen := encryptLength / 8
	if realLen > maxLen {
		return nil, fmt.Errorf("Not Support %d, Only Support Lower then %d [% x]", realLen, maxLen, hashs)
	}

	return hashs[0:realLen], nil
}

// SHA1 SHA1
func SHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// EcbDecrypt 解密
//func EcbDecrypt(data, key []byte) []byte {
//	block, _ := aes.NewCipher(key)
//	decrypted := make([]byte, len(data))
//	size := block.BlockSize()
//	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
//		block.Decrypt(decrypted[bs:be], data[bs:be])
//	}
//	return PKCS5UnPadding(decrypted)
//}

// EcbEncrypt 加密
func EcbEncrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	data = PKCS5Padding(data, block.BlockSize())
	decrypted := make([]byte, len(data))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Encrypt(decrypted[bs:be], data[bs:be])
	}
	return decrypted
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//func PKCS5UnPadding(origData []byte) []byte {
//	length := len(origData)
//	// 去掉最后一个字节 unpadding 次
//	unpadding := int(origData[length-1])
//	return origData[:(length - unpadding)]
//}
