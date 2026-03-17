package pathtraversal

import (
	"net/http"
	"os"
	"path/filepath"
)

const baseDir = "/var/www/files"

// VULN 1: os.ReadFile with string concatenation - no path sanitization
func ReadUserFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	path := baseDir + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}

// VULN 2: http.ServeFile with user-controlled path - allows ../../etc/passwd
func DownloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	fullPath := filepath.Join(baseDir, filename)
	http.ServeFile(w, r, fullPath)
}

// VULN 3: os.Open with user-controlled path - stream arbitrary files
func ExportReport(w http.ResponseWriter, r *http.Request) {
	reportName := r.URL.Query().Get("name")
	fullPath := filepath.Join("/reports/output", reportName)
	f, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
	data, _ := os.ReadFile(fullPath)
	w.Write(data)
}
