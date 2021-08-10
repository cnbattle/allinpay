package utils

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEcbEncrypt(t *testing.T) {
	type args struct {
		data []byte
		key  []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"test", args{[]byte("cnbattle"), []byte("WaHVZNHZYX3v4si1bBTVseIwEMPMcKzz")}, "222c165839da6c857d164dd45d975716"},
		{"test", args{[]byte("allin"), []byte("WaHVZNHZYX3v4si1bBTVseIwEMPMcKzz")}, "2cd39b5edb9de7dbd7caafc4951e27f5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EcbEncrypt(tt.args.data, tt.args.key); !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("hex.EncodeToString(EcbEncrypt()) = %v, want %v", hex.EncodeToString(got), tt.want)
			}
		})
	}
}

func TestEcbDecrypt(t *testing.T) {
	type args struct {
		data string
		key  []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"test", args{"222c165839da6c857d164dd45d975716", []byte("WaHVZNHZYX3v4si1bBTVseIwEMPMcKzz")}, "cnbattle"},
		{"test", args{"2cd39b5edb9de7dbd7caafc4951e27f5", []byte("WaHVZNHZYX3v4si1bBTVseIwEMPMcKzz")}, "allin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decodeString, err := hex.DecodeString(tt.args.data)
			if err != nil {
				t.Fatal(err)
			}
			if got := EcbDecrypt(decodeString, tt.args.key); !reflect.DeepEqual(string(got), tt.want) {
				t.Errorf("string(EcbDecrypt()) = %v, want %v", string(got), tt.want)
			}
		})
	}
}
