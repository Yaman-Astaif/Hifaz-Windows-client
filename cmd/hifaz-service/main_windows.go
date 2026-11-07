// Command hifaz-service is the Hifaz service. Windows starts it; the
// installer also runs "hifaz-service.exe cleanup" when Hifaz is removed.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/service"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "cleanup" {
		if err := service.Cleanup(); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
			os.Exit(1)
		}
		return
	}
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		fmt.Fprintln(os.Stderr, "hifaz-service is started by Windows as the Hifaz service.")
		os.Exit(2)
	}
	if err := service.Run(); err != nil {
		os.Exit(1)
	}
}
