package pathtraversal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

const staticDir = "/var/www/static"

// VULN 1: os.ReadDir with user-controlled directory - exposes arbitrary directory contents
func BrowseDirectory(w http.ResponseWriter, r *http.Request) {
	subdir := r.URL.Query().Get("dir")
	target := filepath.Join(staticDir, subdir)
	entries, err := os.ReadDir(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	json.NewEncoder(w).Encode(names)
}

// VULN 2: os.ReadFile with fmt.Sprintf path - user controls name and type
func ServeAsset(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	assetType := r.URL.Query().Get("type")
	filePath := fmt.Sprintf("%s/%s/%s", staticDir, assetType, name)
	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(data)
}

// VULN 3: os.WriteFile with user-controlled destination - write to arbitrary path
func CopyTemplate(w http.ResponseWriter, r *http.Request) {
	template := r.URL.Query().Get("template")
	dest := r.URL.Query().Get("dest")
	src := filepath.Join(staticDir, "templates", template)
	data, err := os.ReadFile(src)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	os.WriteFile(dest, data, 0644)
	w.Write([]byte("copied"))
}
