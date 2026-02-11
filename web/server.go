// server.go provides the HTTP server and routing for the web UI.
// Serves embedded static files and API routes for domain decode/classify/extract/analyze.
//
// @decision: Use stdlib net/http and embed.FS rather than a framework. The API surface
// is small (4 endpoints + static files) and adding a dependency like chi or gin is not
// justified. The embed.FS approach means zero runtime file dependencies.
package web

import (
	"fmt"
	"io/fs"
	"net/http"
)

// Serve starts the web server on the given address and port.
func Serve(addr string, port int) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("POST /api/decode", handleDecode)
	mux.HandleFunc("POST /api/classify", handleClassify)
	mux.HandleFunc("POST /api/extract", handleExtract)
	mux.HandleFunc("POST /api/analyze", handleAnalyze)

	// Static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to create static sub-filesystem: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	listenAddr := fmt.Sprintf("%s:%d", addr, port)
	fmt.Printf("roast web UI: http://%s\n", listenAddr)
	return http.ListenAndServe(listenAddr, mux)
}
