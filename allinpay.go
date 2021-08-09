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
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

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
}

type Client struct {
	appID        string
	appSecretKey string
	appAccountID string
	pfxPath      string
	tlCert       string
	pfxPwd       string
	serviceUrl   string
	version      string
}

func NewAllInPayClient(config Config) *Client {
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

	//环境	HTTPS请求地址
	//测试环境	http://test.allinpay.com/op/gateway
	//正式环境	https://cloud.allinpay.com/gateway
	serviceUrl := "http://test.allinpay.com/op/gateway"
	if config.IsProd {
		serviceUrl = "https://cloud.allinpay.com/gateway"
	}
	if len(config.Version) == 0 {
		config.Version = "1.0"
	}

	return &Client{
		appID:        config.AppID,
		appSecretKey: config.AppSecretKey,
		appAccountID: config.AppAccountID,
		pfxPath:      config.PfxPath,
		pfxPwd:       config.PfxPwd,
		tlCert:       config.TLCert,
		serviceUrl:   serviceUrl,
		version:      config.Version,
	}
}

var httpClient *http.Client

func (s *Client) Request(method string, content map[string]string) (data interface{}, err error) {
	paramsBbytes, err := json.Marshal(content)
	if err != nil {
		panic(err)
	}
	params := map[string]string{}
	params["appId"] = s.appID
	params["method"] = method
	params["charset"] = "utf-8"
	params["format"] = "JSON"
	params["timestamp"] = time.Now().Format("2006-01-02 15:04:05")
	//params["timestamp"] = "2021-08-09 11:19:10"
	params["version"] = s.version
	params["bizContent"] = string(paramsBbytes)
	sign, err := s.sign(params)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign
	params["signType"] = "SHA256WithRSA"

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
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("Body.Close() err:" + err.Error())
		}
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
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
		panic(err)
	}
	return result, nil
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
	privateKey, err := s.getPrivateKey(s.pfxPath, s.pfxPwd)
	if err != nil {
		return "", err
	}
	shaNew := sha256.New()
	shaNew.Write([]byte(sb))
	hashed := shaNew.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifyResult 验参
func (s *Client) verifyResult(jsonStr, sign string) error {
	encodingSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	h := md5.New()
	h.Write([]byte(jsonStr))
	sb := base64.StdEncoding.EncodeToString(h.Sum(nil))
	caCert, err := ioutil.ReadFile(s.tlCert)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(caCert)
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	shaNew := sha256.New()
	shaNew.Write([]byte(sb))
	sum := shaNew.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, sum, encodingSign)
	return err
}

// getPrivateKey 获取私钥
func (s *Client) getPrivateKey(privateKeyName, privatePassword string) (*rsa.PrivateKey, error) {
	f, err := os.Open(privateKeyName)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	// 因为pfx证书公钥和密钥是成对的，所以要先转成pem.Block
	blocks, err := pkcs12.ToPEM(privateKeyBytes, privatePassword)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 2 {
		return nil, errors.New("解密错误")
	}
	// 拿到第一个block，用x509解析出私钥（当然公钥也是可以的）
	privateKey, err := x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}