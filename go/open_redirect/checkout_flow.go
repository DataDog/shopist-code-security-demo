package openredirect

import (
	"net/http"
)

// VULN 1: Unvalidated `next` query param used directly in redirect after login - open redirect
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := r.URL.Query().Get("next")
	if !authenticateUser(username, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// VULN 2: Unvalidated `return_url` query param used in redirect after checkout complete - open redirect
func CheckoutCompleteHandler(w http.ResponseWriter, r *http.Request) {
	orderID := r.FormValue("order_id")
	returnURL := r.URL.Query().Get("return_url")
	if orderID == "" {
		http.Error(w, "Missing order ID", http.StatusBadRequest)
		return
	}
	if returnURL == "" {
		returnURL = "/orders/" + orderID
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// VULN 3: OAuth state param decoded directly as redirect target - open redirect after OAuth callback
func OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing OAuth code", http.StatusBadRequest)
		return
	}
	_ = exchangeOAuthCode(code)
	http.Redirect(w, r, state, http.StatusFound)
}

func authenticateUser(username, password string) bool { return true }
func exchangeOAuthCode(code string) string             { return "" }
