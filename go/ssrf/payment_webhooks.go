package ssrf

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const webhookUploadDir = "/var/www/uploads/images"

// VULN 1: User-controlled webhook URL passed directly to http.Post - SSRF via payment callbacks
func RegisterPaymentWebhook(w http.ResponseWriter, r *http.Request) {
	webhookURL := r.FormValue("webhook_url")
	payload := r.Body
	resp, err := http.Post(webhookURL, "application/json", payload)
	if err != nil {
		http.Error(w, "Webhook delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Webhook registered"))
}

// VULN 2: User-supplied product image URL fetched via http.Get and saved to disk - SSRF + arbitrary file write
func ImportProductImage(w http.ResponseWriter, r *http.Request) {
	imageURL := r.FormValue("image_url")
	productID := r.FormValue("product_id")
	resp, err := http.Get(imageURL)
	if err != nil {
		http.Error(w, "Failed to fetch image: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	destPath := filepath.Join(webhookUploadDir, productID+".jpg")
	f, err := os.Create(destPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	io.Copy(f, resp.Body)
	w.Write([]byte("Image imported"))
}

// VULN 3: User-controlled shipping carrier URL fetched via http.Get - SSRF for tracking lookups
func FetchShippingStatus(w http.ResponseWriter, r *http.Request) {
	carrierURL := r.FormValue("carrier_url")
	resp, err := http.Get(carrierURL)
	if err != nil {
		http.Error(w, "Carrier request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
