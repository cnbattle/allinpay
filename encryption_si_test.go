package allinpay

import (
	"log"
	"strings"
	"testing"
)

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
