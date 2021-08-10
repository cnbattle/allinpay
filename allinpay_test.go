package allinpay

import (
	"log"
	"strings"
	"testing"
)

func TestNewAliInPayClient(t *testing.T) {
	client := NewAllInPayClient(Config{
		AppID:        "10000",
		AppSecretKey: "xxxxxxxxxxxxxxxxxxxxxxxx",
		AppAccountID: "40000",
		PfxPath:      "./tests/user-rsa.pfx",
		TLCert:       "./tests/public-rsa.cer",
		PfxPwd:       "123456",
		IsProd:       false,
	})
	params := map[string]string{}
	params["bizUserId"] = "golang-test-1"
	params["memberType"] = "3"
	params["source"] = "1"
	data, err := client.Request("allinpay.yunst.memberService.createMember", params)
	log.Println(data)
	log.Println(err)
}

func TestClient_EncryptionSI(t *testing.T) {
	client := NewAllInPayClient(Config{
		AppSecretKey: "WaHVZNHZYX3v4si1bBTVseIwEMPMcKzz",
	})
	data, err := client.EncryptionSI("320721199408140000")
	log.Println(data)
	log.Println(err)
	if !strings.EqualFold(data, "92F647AC47B4F65382929373B00BEF7DC95B60519796541505716B22E62FEDBA") {
		t.Fatal(err)
	}
}
