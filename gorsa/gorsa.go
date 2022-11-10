package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
)

// 公钥加密
func PublicEncrypt(data, pubPEM string) ([]byte, error) {

	grsa := RSASecurity{}
	grsa.SetPublicKey(pubPEM)

	rsadata, err := grsa.PubKeyENCTYPT([]byte(data))
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}

// 私钥加密
func PriKeyEncrypt(data, priPEM string) ([]byte, error) {

	grsa := RSASecurity{}
	grsa.SetPrivateKey(priPEM)

	rsadata, err := grsa.PriKeyENCTYPT([]byte(data))
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}

// 公钥解密
func PublicDecrypt(data []byte, pubPEM string) ([]byte, error) {

	grsa := RSASecurity{}
	if err := grsa.SetPublicKey(pubPEM); err != nil {
		return nil, err
	}

	rsadata, err := grsa.PubKeyDECRYPT(data)
	if err != nil {
		return nil, err
	}
	return rsadata, nil
}

// 私钥解密
func PriKeyDecrypt(data []byte, priPEM string) ([]byte, error) {

	grsa := RSASecurity{}

	if err := grsa.SetPrivateKey(priPEM); err != nil {
		return nil, err
	}

	rsadata, err := grsa.PriKeyDECRYPT(data)
	if err != nil {
		return nil, err
	}

	return rsadata, nil
}

// RSANoPadding,modulus为16进制字符串,仅适合0-255的字符加密
func PubKeyEncrypt_NoPad(msg, hexE, hexN string, args ...interface{}) []byte {
	c := new(big.Int)

	switch args {
	case nil:
		//逆序msg字符串  仅适合0-255的字符
		bytes := []byte(msg)
		for from, to := 0, len(bytes)-1; from < to; from, to = from+1, to-1 {
			bytes[from], bytes[to] = bytes[to], bytes[from]
		}
		c.SetBytes(bytes)
	default:
		c.SetBytes([]byte(msg))
	}

	bigN := new(big.Int)
	bigN.SetString(hexN, 16)
	bigE := new(big.Int)
	bigE.SetString(hexE, 16)

	bigRsbyte := c.Exp(c, bigE, bigN).Bytes()
	return bigRsbyte
}

// 仅适合0-255的字符加密
func PriKeyDecrypt_NoPad(msg []byte, priPEM string) string {
	pri, _ := GetPriKey([]byte(priPEM))
	c := new(big.Int).SetBytes(msg)
	plainText := c.Exp(c, pri.D, pri.N).Bytes()
	return string(plainText)
}

func PubKeyEncrypt_E_N(msg, hexE, hexN string) []byte {
	// pubkey, _ := ReadNE(hexN, hexE)
	bigE := new(big.Int)
	bigE.SetString(hexE, 16)
	// fmt.Println(int(bigE.Int64()))
	bigN := new(big.Int)
	bigN.SetString(hexN, 16)
	// temp, _ := base64.RawStdEncoding.DecodeString(hexN)
	// bigN.SetBytes(temp)
	pubkey := &rsa.PublicKey{
		E: int(bigE.Int64()),
		N: bigN,
	}
	resb, _ := rsa.EncryptPKCS1v15(rand.Reader, pubkey, []byte(msg))
	return resb
}

func PubKeyEncrypt_b64(plainText []byte, pubBase64 string) ([]byte, error) {
	// Base64 decode.
	publicKeyBinary, err := base64.StdEncoding.DecodeString(pubBase64)
	if err != nil {
		return nil, err
	}

	rsaPk, err := x509.ParsePKIXPublicKey(publicKeyBinary)
	if err != nil {
		return nil, err
	}
	if err != nil {
		rsaPk, err = x509.ParsePKCS1PublicKey(publicKeyBinary)
		if err != nil {
			return nil, err
		}
	}
	var pubKey *rsa.PublicKey = rsaPk.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}
