package pathtraversal

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadDir = "/var/www/uploads"

// VULN 1: Write uploaded file to user-specified destination - arbitrary file write
func UploadFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	dest := r.FormValue("destination")
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	savePath := filepath.Join(uploadDir, dest)
	out, _ := os.Create(savePath)
	defer out.Close()
	io.Copy(out, file)
	w.Write([]byte("uploaded"))
}

// VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
func ExtractArchive(w http.ResponseWriter, r *http.Request) {
	extractTo := r.FormValue("extract_to")
	archivePath := filepath.Join(uploadDir, r.FormValue("archive"))
	zr, _ := zip.OpenReader(archivePath)
	defer zr.Close()
	for _, f := range zr.File {
		// zip slip: f.Name may contain ../ sequences
		destPath := filepath.Join(extractTo, f.Name)
		out, _ := os.Create(destPath)
		rc, _ := f.Open()
		io.Copy(out, rc)
		rc.Close()
		out.Close()
	}
	w.Write([]byte("extracted"))
}

// VULN 3: Read file using user-controlled filename - path traversal on read
func PreviewUpload(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	filename := r.URL.Query().Get("file")
	path := uploadDir + "/" + username + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}
