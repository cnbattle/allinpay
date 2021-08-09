# allinpay

## Demo
```go
package main

import (
	"log"
	
	"github.com/cnbattle/allinpay"
)

func main() {
	client := allinpay.NewAllInPayClient(allinpay.Config{
		AppID:        "xxx",
		AppSecretKey: "xxx",
		AppAccountID: "40000",
		PfxPath:      "./1581648210684.pfx",
		TLCert:       "./TLCert-test.cer",
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

```