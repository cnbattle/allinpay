package allinpay

import (
	"strings"
	"testing"
)

func TestClient_sign(t *testing.T) {
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

	sign, err := client.sign(params)
	if err != nil {
		t.Errorf("client.sign error:%s", err)
	}
	yes := "BgOQmW5N2xjm3hRPwiVom6YRj6BBv8tdQgRKWOVTb3U0oET6qL9UOwjHv6u1TSDrEok6dLxA77C3DdEhpKs5NWKffqSAB4mhSGsXg/Vb6AkmJYbvJd7R/DmKMEk3VTc3N4tPySG1r7E4mlXuwLraLBLRY1/sVTLjgZZ++uLWUBCvOlLoPu7jo+IbhJ8UIkaQAAkrGjuiRBjk+uRhMDzO8Sgmpt/tdkVlOGaH3P3duQQ5mOjw5Bm20WwUGnAKOSPpByDSEgEj12zvWYSPuMWM8wgy8Ww4tL8q9d8cxX5ywRuWACNQ1L0pHZiDHtZdaO5txApwzt+Jvs3py0hM7KtuPD7kV6zWz5KuFm5d/I0JuH0jpPHwQ14KZNnRVOn/llgAoxjR5NIf19SlLrLIlskYr91aoDo+AKcohCZSdMBy5abFoReIST5rfpGmJ+arZDf2DIXlui/cYM9fS2mbwv7gA+Cb0J4G2B6gf4tG5YMb/CoF+ifOtYF6QluBRwR6/SzR"
	if !strings.EqualFold(sign, yes) {
		t.Errorf("sign tests error")
	}
}
