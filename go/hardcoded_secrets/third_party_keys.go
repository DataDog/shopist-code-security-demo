package hardcodedsecrets

import (
	"fmt"
	"net/http"
)

// VULN 1: Hardcoded SendGrid API key - promotional email campaigns
func SendPromoEmail(toEmail, promoCode string) error {
	sendgridAPIKey := "SG.aBcDeFgHiJkLmNoPqRsTuV.WxYz1234567890abcdefghijklmnopqrstuvwxyz12"
	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+sendgridAPIKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// VULN 2: Hardcoded Google Maps API key - store locator feature
func GetStoreLocation(address string) (string, error) {
	googleMapsAPIKey := "AIzaSyDdI0hiBtXV-3Zr5elSHVQG8mEVRnS_kXc"
	url := fmt.Sprintf(
		"https://maps.googleapis.com/maps/api/geocode/json?address=%s&key=%s",
		address, googleMapsAPIKey,
	)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return url, nil
}

// VULN 3: Hardcoded Twilio SID and auth token - SMS order notifications
func SendOrderSMS(toPhone, message string) error {
	twilioAccountSID := "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	twilioAuthToken := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", twilioAccountSID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(twilioAccountSID, twilioAuthToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
