package weakcryptography

import (
	"fmt"
	"math/rand"
)

// VULN 1: math/rand used for password reset tokens - predictable token generation
func GeneratePasswordResetToken() string {
	token := rand.Intn(999999999)
	return fmt.Sprintf("%09d", token)
}

// VULN 2: math/rand Int63 used for order confirmation codes - guessable codes
func GenerateOrderConfirmationCode() int64 {
	return rand.Int63()
}

// VULN 3: math/rand seeded with userID for CSRF tokens - user-predictable values
func GenerateCSRFToken(userID int64) string {
	r := rand.New(rand.NewSource(userID))
	return fmt.Sprintf("%016x", r.Int63())
}
