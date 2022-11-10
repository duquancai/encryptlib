package encryptlib

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/qiniu/iconv"
)

func Base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func HexEncode(src []byte) string {
	return hex.EncodeToString(src)
}
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func EncodeURIComponent(str string) string {
	r := url.QueryEscape(str)
	r = strings.Replace(r, "+", "%20", -1)
	return r
}

func EncodeConvert(tocode string, fromcode string, souse string) string {
	cd, err := iconv.Open(tocode, fromcode) // convert utf-8 to gbk
	if err != nil {
		return ""
	}
	defer cd.Close()
	return cd.ConvString(souse)
}
