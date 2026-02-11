// embed.go embeds the static web assets (HTML, CSS, JS) into the Go binary
// via go:embed so the web UI requires no external files at runtime.
package web

import "embed"

//go:embed static/*
var staticFiles embed.FS
