// Command winres writes the Windows resources of a Hifaz program (icon,
// version information, manifest) as a .syso file next to its main
// package, and optionally the icon as an .ico file for the installer.
//
//	go run ./tools/winres -arch amd64 -version 0.1.2 -name hifaz.exe \
//	    -description "Hifaz" -out cmd/hifaz/rsrc_windows_amd64.syso [-ico build/hifaz.ico]
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/icon"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/winres"
)

func main() {
	arch := flag.String("arch", "", "GOARCH: amd64 or arm64")
	ver := flag.String("version", "", "X.Y.Z")
	name := flag.String("name", "", "the program's file name")
	desc := flag.String("description", "", "the program's description")
	out := flag.String("out", "", "the .syso file to write")
	ico := flag.String("ico", "", "also write the icon to this .ico file")
	flag.Parse()
	if err := run(*arch, *ver, *name, *desc, *out, *ico); err != nil {
		fmt.Fprintln(os.Stderr, "winres:", err)
		os.Exit(1)
	}
}

func run(arch, ver, name, desc, out, ico string) error {
	if arch == "" || ver == "" || name == "" || out == "" {
		return fmt.Errorf("-arch, -version, -name and -out are needed")
	}
	entries, err := icon.Entries()
	if err != nil {
		return err
	}
	vi, err := winres.VersionInfo{
		Version: ver, ProductName: "Hifaz", Description: desc,
		Company: version.Developer, FileName: name,
		Copyright: "Copyright (C) 2026 " + version.Developer,
	}.Data()
	if err != nil {
		return err
	}
	const firstIcon = 1
	res := []winres.Resource{
		{Type: winres.TypeGroupIcon, ID: 1, Data: icon.GroupResource(entries, firstIcon)},
		{Type: winres.TypeVersion, ID: 1, Data: vi},
		{Type: winres.TypeManifest, ID: 1, Data: winres.Manifest("Hifaz."+strings.TrimSuffix(name, ".exe"), ver)},
	}
	for i, e := range entries {
		res = append(res, winres.Resource{Type: winres.TypeIcon, ID: uint16(firstIcon + i), Data: e.PNG})
	}
	obj, err := winres.Object(arch, res)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, obj, 0o644); err != nil {
		return err
	}
	if ico != "" {
		return os.WriteFile(ico, icon.ICO(entries), 0o644)
	}
	return nil
}
