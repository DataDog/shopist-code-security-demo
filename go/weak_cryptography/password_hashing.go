package weakcryptography

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// VULN 1: MD5 used for password hashing - user account registration
func HashUserPassword(password string) string {
	h := md5.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// VULN 2: SHA1 used for password storage - legacy user migration
func HashPasswordSHA1(password, username string) string {
	h := sha1.New()
	h.Write([]byte(username + password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// VULN 3: HMAC with MD5 used for order integrity verification
func ComputeOrderHMAC(orderData, secretKey string) string {
	mac := hmac.New(md5.New, []byte(secretKey))
	mac.Write([]byte(orderData))
	return hex.EncodeToString(mac.Sum(nil))
}
