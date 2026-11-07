// Package ui holds the window's pages, embedded in the app.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed web
var files embed.FS

// Files is the page tree: index.html and assets/.
var Files, _ = fs.Sub(files, "web")
