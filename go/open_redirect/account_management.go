package openredirect

import (
	"net/http"
)

// VULN 1: Unvalidated `redirect_to` param used in redirect after password reset confirm - open redirect
func PasswordResetConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	newPassword := r.FormValue("new_password")
	redirectTo := r.URL.Query().Get("redirect_to")
	if !validateResetToken(token) {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}
	_ = updatePassword(token, newPassword)
	if redirectTo == "" {
		redirectTo = "/login"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// VULN 2: Referer header used directly as logout redirect destination - open redirect
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		MaxAge: -1,
	})
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/login"
	}
	http.Redirect(w, r, referer, http.StatusFound)
}

// VULN 3: Unvalidated `callback_url` used in redirect after social account linking - open redirect
func SocialLinkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	code := r.URL.Query().Get("code")
	callbackURL := r.URL.Query().Get("callback_url")
	if provider == "" || code == "" {
		http.Error(w, "Missing provider or code", http.StatusBadRequest)
		return
	}
	_ = linkSocialAccount(provider, code)
	if callbackURL == "" {
		callbackURL = "/account/settings"
	}
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

func validateResetToken(token string) bool             { return true }
func updatePassword(token, newPassword string) error   { return nil }
func linkSocialAccount(provider, code string) error    { return nil }
