package ssrf

import (
	"encoding/json"
	"io"
	"net/http"
)

// VULN 1: User-supplied source URL fetched via http.Get - SSRF for product data import
func ImportProductData(w http.ResponseWriter, r *http.Request) {
	sourceURL := r.FormValue("source_url")
	resp, err := http.Get(sourceURL)
	if err != nil {
		http.Error(w, "Failed to fetch product data: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var product map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&product)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(product)
}

// VULN 2: User-supplied RSS feed URL fetched via http.Get - SSRF for blog/deal aggregation
func FetchDealsFeed(w http.ResponseWriter, r *http.Request) {
	feedURL := r.FormValue("feed_url")
	resp, err := http.Get(feedURL)
	if err != nil {
		http.Error(w, "Failed to fetch feed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/xml")
	w.Write(body)
}

// VULN 3: User-controlled API base URL string-concatenated then fetched via http.Get - SSRF for price sync
func SyncExternalPricing(w http.ResponseWriter, r *http.Request) {
	apiBase := r.FormValue("api_base")
	productSKU := r.FormValue("sku")
	url := apiBase + "/products/" + productSKU + "/price"
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Price sync failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}
