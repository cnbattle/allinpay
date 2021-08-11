package allinpay

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cnbattle/allinpay/utils"

	"golang.org/x/crypto/pkcs12"
)

type Config struct {
	AppID        string
	AppSecretKey string
	AppAccountID string
	PfxPath      string
	TLCert       string
	PfxPwd       string
	IsProd       bool
	Version      string
	NotifyUrl    string
	Debug        bool
}

type Client struct {
	AppID        string
	AppSecretKey string
	AppAccountID string
	PfxPath      string
	TLCert       string
	PfxPwd       string
	serviceUrl   string
	notifyUrl    string
	version      string
	debug        bool
}

func NewAllInPayClient(config Config) *Client {
	if len(config.TLCert) > 0 {
		caCert, err := ioutil.ReadFile(config.TLCert)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: true,
				},
			},
		}
	}
	serviceUrl := "http://test.allinpay.com/op/gateway"
	if config.IsProd {
		serviceUrl = "https://cloud.allinpay.com/gateway"
	}
	if len(config.Version) == 0 {
		config.Version = "1.0"
	}

	return &Client{
		AppID:        config.AppID,
		AppSecretKey: config.AppSecretKey,
		AppAccountID: config.AppAccountID,
		PfxPath:      config.PfxPath,
		PfxPwd:       config.PfxPwd,
		TLCert:       config.TLCert,
		notifyUrl:    config.NotifyUrl,
		serviceUrl:   serviceUrl,
		version:      config.Version,
		debug:        config.Debug,
	}
}

var httpClient *http.Client

func (s *Client) Request(method string, content map[string]interface{}) (data string, err error) {
	paramsBytes, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}
	params := map[string]string{}
	params["appId"] = s.AppID
	params["notifyUrl"] = s.notifyUrl
	params["method"] = method
	params["charset"] = "utf-8"
	params["format"] = "JSON"
	params["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	params["version"] = s.version
	params["bizContent"] = string(paramsBytes)
	sign, err := s.sign(params)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}
	params["sign"] = sign
	params["signType"] = "SHA256WithRSA"

	if s.debug {
		marshal, _ := json.Marshal(params)
		log.Println("request:", string(marshal))
	}

	var keyList []string
	for k := range params {
		keyList = append(keyList, k)
	}
	u := url.Values{}
	sort.Strings(keyList)
	for _, k := range keyList {
		if v, ok := params[k]; ok && len(v) > 0 {
			u.Set(k, v)
		}
	}
	resp, err := httpClient.Post(s.serviceUrl, "application/x-www-form-urlencoded;charset=utf-8",
		bytes.NewBuffer([]byte(u.Encode())))
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Body.Close() err:" + err.Error())
		}
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}

	if s.debug {
		log.Println("response:", string(body))
	}

	result := map[string]interface{}{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}
	verifySign := result["sign"]
	delete(result, "sign")
	resultJsonStr, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	delete(result, "sign")
	err = s.verifyResult(string(resultJsonStr), verifySign.(string))
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), RequestError)
	}
	return string(body), nil
}

// sign 签名
func (s *Client) sign(params map[string]string) (string, error) {
	delete(params, "signType")
	var (
		buf     strings.Builder
		keyList []string
	)
	for k := range params {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)
	for _, k := range keyList {
		if v, ok := params[k]; ok && len(v) > 0 {
			buf.WriteString(k)
			buf.WriteByte('=')
			buf.WriteString(v)
			buf.WriteByte('&')
		}
	}
	h := md5.New()
	h.Write([]byte(buf.String())[:buf.Len()-1])
	sb := base64.StdEncoding.EncodeToString(h.Sum(nil))
	privateKey, err := s.getPrivateKey(s.PfxPath, s.PfxPwd)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), SignError)
	}
	shaNew := sha256.New()
	shaNew.Write([]byte(sb))
	hashed := shaNew.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), SignError)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// EncryptionSI RSA加密敏感信息
func (s *Client) EncryptionSI(information string) (string, error) {
	key, err := utils.AesSha1PRNG([]byte(s.AppSecretKey), 128)
	if err != nil {
		return "", fmt.Errorf("%v: [%w]", err.Error(), EncryptionSIError)
	}
	encrypt := utils.EcbEncrypt([]byte(information), key)
	return strings.ToUpper(hex.EncodeToString(encrypt)), nil
}

// verifyResult 验参
func (s *Client) verifyResult(jsonStr, sign string) error {
	encodingSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("%v: [%w]", err.Error(), VerifyResultError)
	}
	h := md5.New()
	h.Write([]byte(jsonStr))
	sb := base64.StdEncoding.EncodeToString(h.Sum(nil))
	caCert, err := ioutil.ReadFile(s.TLCert)
	if err != nil {
		return fmt.Errorf("%v: [%w]", err.Error(), VerifyResultError)
	}
	block, _ := pem.Decode(caCert)
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%v: [%w]", err.Error(), VerifyResultError)
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	shaNew := sha256.New()
	shaNew.Write([]byte(sb))
	sum := shaNew.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, sum, encodingSign)
	if err != nil {
		return fmt.Errorf("%v: [%w]", err.Error(), VerifyResultError)
	}
	return nil
}

// getPrivateKey 获取私钥
func (s *Client) getPrivateKey(privateKeyName, privatePassword string) (*rsa.PrivateKey, error) {
	f, err := os.Open(privateKeyName)
	if err != nil {
		return nil, fmt.Errorf("%v: [%w]", err.Error(), GetPrivateKeyError)
	}
	privateKeyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("%v: [%w]", err.Error(), GetPrivateKeyError)
	}
	// 因为pfx证书公钥和密钥是成对的，所以要先转成pem.Block
	blocks, err := pkcs12.ToPEM(privateKeyBytes, privatePassword)
	if err != nil {
		return nil, fmt.Errorf("%v: [%w]", err.Error(), GetPrivateKeyError)
	}
	if len(blocks) != 2 {
		return nil, fmt.Errorf("kcs12.ToPEM error: [%w]", GetPrivateKeyError)
	}
	var der = blocks[0].Bytes
	if strings.EqualFold(blocks[1].Type, "PRIVATE KEY") {
		der = blocks[1].Bytes
	}
	// 拿到第一个block，用x509解析出私钥（当然公钥也是可以的）
	privateKey, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%v: [%w]", err.Error(), GetPrivateKeyError)
	}
	return privateKey, nil
}
