//go:build !windows

// Command hifaz-service is the Hifaz service; it runs on Windows only.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "hifaz-service runs on Windows only.")
	os.Exit(2)
}
