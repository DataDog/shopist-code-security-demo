package xxe

import (
	"encoding/xml"
	"io"
	"net/http"
	"strings"

	"github.com/antchfx/xmlquery"
	"github.com/beevik/etree"
)

type ProductCatalog struct {
	XMLName  xml.Name  `xml:"catalog"`
	Products []Product `xml:"product"`
}

type Product struct {
	ID          string  `xml:"id"`
	Name        string  `xml:"name"`
	Description string  `xml:"description"`
	Price       float64 `xml:"price"`
	SKU         string  `xml:"sku"`
}

// VULN 1: xml.NewDecoder on user-supplied request body without disabling external entities - XXE
func ImportProductCatalog(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	decoder := xml.NewDecoder(r.Body)
	var catalog ProductCatalog
	if err := decoder.Decode(&catalog); err != nil {
		http.Error(w, "Failed to parse XML: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Imported products"))
}

// VULN 2: etree library parsing user-supplied XML without disabling entity expansion - XXE
func UpdateProductsFromXML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		http.Error(w, "Invalid XML: "+err.Error(), http.StatusBadRequest)
		return
	}
	products := doc.FindElements("//product")
	w.Write([]byte("Updated " + string(rune(len(products))) + " products"))
}

// VULN 3: xmlquery.Parse on user-supplied XML bytes without entity protection - XXE
func SearchProductXML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	doc, err := xmlquery.Parse(strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "XML parse error: "+err.Error(), http.StatusBadRequest)
		return
	}
	nodes := xmlquery.Find(doc, "//product/name")
	for _, n := range nodes {
		w.Write([]byte(n.InnerText() + "\n"))
	}
}
