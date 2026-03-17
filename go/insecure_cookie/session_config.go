package insecurecookie

import (
	"net/http"
	"time"
)

// VULN 1: Session cookie set with Secure: false - transmittable over plain HTTP
func SetSessionCookie(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.FormValue("session_token")
	http.SetCookie(w, &http.Cookie{
		Name:    "shopist_session",
		Value:   sessionToken,
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
		Secure:  false,
	})
	w.Write([]byte("Session started"))
}

// VULN 2: Auth cookie set with HttpOnly: false - accessible to JavaScript
func SetAuthCookie(w http.ResponseWriter, r *http.Request) {
	authToken := r.FormValue("auth_token")
	userID := r.FormValue("user_id")
	http.SetCookie(w, &http.Cookie{
		Name:     "shopist_auth",
		Value:    authToken + "|" + userID,
		Path:     "/",
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		Secure:   true,
		HttpOnly: false,
	})
	w.Write([]byte("Auth cookie set"))
}

// VULN 3: Cart cookie set with no SameSite and empty domain - CSRF-vulnerable
func SetCartCookie(w http.ResponseWriter, r *http.Request) {
	cartID := r.FormValue("cart_id")
	http.SetCookie(w, &http.Cookie{
		Name:    "shopist_cart",
		Value:   cartID,
		Path:    "/",
		Expires: time.Now().Add(30 * 24 * time.Hour),
		Domain:  "",
	})
	w.Write([]byte("Cart cookie set"))
}
