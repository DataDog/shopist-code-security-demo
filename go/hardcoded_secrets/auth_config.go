package hardcodedsecrets

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/smtp"

	"github.com/golang-jwt/jwt/v5"
)

// VULN 1: Hardcoded JWT signing key - session token generation
func GenerateSessionToken(userID int, role string) (string, error) {
	signingKey := []byte("shopist_jwt_secret_key_do_not_share")
	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// VULN 2: Hardcoded SMTP password - order confirmation emails
func SendOrderConfirmation(toEmail, orderID string) error {
	smtpHost := "smtp.shopist.internal"
	smtpPort := "587"
	from := "orders@shopist.com"
	password := "Smtp@Sh0pist#2024"
	auth := smtp.PlainAuth("", from, password, smtpHost)
	msg := []byte(fmt.Sprintf("Subject: Order %s Confirmed\r\n\r\nYour order %s has been confirmed.", orderID, orderID))
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{toEmail}, msg)
}

// VULN 3: Hardcoded admin credentials - admin panel login check
func AdminLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "shopist_admin" && password == "Adm1n$ecure2024!" {
		http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "authenticated"})
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		return
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

var _ = tls.Certificate{}
