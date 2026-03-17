package weakcryptography

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
)

// VULN 1: DES cipher used for payment card data encryption
func EncryptCardData(cardNumber string, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := []byte(cardNumber)
	for len(padded)%des.BlockSize != 0 {
		padded = append(padded, 0)
	}
	dst := make([]byte, len(padded))
	block.Encrypt(dst, padded)
	return dst, nil
}

// VULN 2: RC4 used for session data encryption
func EncryptSessionData(sessionPayload string, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src := []byte(sessionPayload)
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return dst, nil
}

// VULN 3: AES in ECB-equivalent mode (manual block-by-block without IV) for PII encryption
func EncryptPIIData(pii string, block cipher.Block) []byte {
	blockSize := block.BlockSize()
	src := []byte(pii)
	for len(src)%blockSize != 0 {
		src = append(src, 0)
	}
	dst := make([]byte, len(src))
	// ECB: each block encrypted independently, no IV, no chaining
	for i := 0; i < len(src); i += blockSize {
		block.Encrypt(dst[i:i+blockSize], src[i:i+blockSize])
	}
	return dst
}
