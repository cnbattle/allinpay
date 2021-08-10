package allinpay

import "errors"

var (
	RequestError       = errors.New("request result error")
	VerifyResultError  = errors.New("verify result error")
	SignError          = errors.New("sign error")
	GetPrivateKeyError = errors.New("get private key error")
	EncryptionSIError  = errors.New("encryption sensitive information error")
)
