package encryptlib

import (
	"bytes"
)

func padSize(dataSize, blockSize int) (padding int) {
	padding = blockSize - dataSize%blockSize
	return
}

// Pkcs7
func Pkcs7Padding(text []byte, blockSize int) []byte {
	paddingSize := blockSize - len(text)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(text, paddingText...)
}
func Pkcs7UnPadding(src []byte) []byte {
	n := len(src)
	if n == 0 {
		return src
	}
	count := int(src[n-1])
	text := src[:n-count]
	return text
}

// Pkcs5
func Pkcs5Padding(text []byte) []byte {
	return Pkcs7Padding(text, 8)
}
func Pkcs5UnPadding(src []byte) []byte {
	return Pkcs7UnPadding(src)
}

// Zero
func ZeroPadding(text []byte, blockSize int) []byte {
	paddingSize := blockSize - len(text)%blockSize
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(text, paddingText...)
}
func ZeroUnPadding(src []byte) []byte {
	return bytes.TrimRight(src, string([]byte{0}))
}

// ISO10126 implements ISO 10126 byte padding. This has been withdrawn in 2007.
func ISO10126Padding(plaintext []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 256 {
		return nil
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append(randBytes(padding-1), byte(padding))
	return append(plaintext, padtext...)
}

func ISO10126UnPadding(ciphertext []byte, blockSize int) []byte {
	length := len(ciphertext)
	if length%blockSize != 0 {
		return nil
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > blockSize || unpadding < 1 {
		return nil
	}
	return ciphertext[:length-unpadding]
}

// ISO97971 Padding Method 2
func ISO97971Padding(plaintext []byte, blockSize int) []byte {
	return ZeroPadding(append(plaintext, 0x80), blockSize)
}

func ISO97971UnPadding(ciphertext []byte, blockSize int) []byte {
	data := ZeroUnPadding(ciphertext)
	return data[:len(data)-1]
}

// ANSIX923 padding
func AnsiX923Padding(plaintext []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		return nil
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append(bytes.Repeat([]byte{byte(0)}, padding-1), byte(padding))
	return append(plaintext, padtext...)
}

func AnsiX923UnPadding(ciphertext []byte, blockSize int) []byte {
	length := len(ciphertext)
	if length%blockSize != 0 {
		return nil
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > blockSize || unpadding < 1 {
		return nil
	}
	if length-unpadding < length-2 {
		pad := ciphertext[length-unpadding : length-2]
		for _, v := range pad {
			if int(v) != 0 {
				return nil
			}
		}
	}
	return ciphertext[0 : length-unpadding]
}
