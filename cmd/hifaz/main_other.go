//go:build !windows

// Command hifaz is the Hifaz app; it runs on Windows only.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "Hifaz runs on Windows only.")
	os.Exit(2)
}
