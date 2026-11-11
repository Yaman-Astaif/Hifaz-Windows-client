// Package winres writes Windows resources (icon, version information,
// manifest) as a COFF object (.syso) that the Go linker adds to a program.
// It covers only what Hifaz needs, so building needs no extra tools.
package winres

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Resource types.
const (
	TypeIcon      = 3
	TypeGroupIcon = 14
	TypeVersion   = 16
	TypeManifest  = 24
)

// langEnUS is the language every resource is stored under.
const langEnUS = 0x0409

// Resource is one resource, identified by type and number.
type Resource struct {
	Type, ID uint16
	Data     []byte
}

// Machines, by GOARCH, with the relocation that makes a data entry's
// address relative to the image (ADDR32NB).
var machines = map[string]struct{ machine, reloc uint16 }{
	"amd64": {0x8664, 0x0003},
	"arm64": {0xAA64, 0x0002},
	"386":   {0x014C, 0x0007},
}

// Object returns a COFF object holding res in a .rsrc section.
func Object(goarch string, res []Resource) ([]byte, error) {
	m, ok := machines[goarch]
	if !ok {
		return nil, fmt.Errorf("winres: unsupported architecture %q", goarch)
	}
	res = append([]Resource(nil), res...)
	sort.SliceStable(res, func(i, j int) bool {
		if res[i].Type != res[j].Type {
			return res[i].Type < res[j].Type
		}
		return res[i].ID < res[j].ID
	})
	for i := 1; i < len(res); i++ {
		if res[i].Type == res[i-1].Type && res[i].ID == res[i-1].ID {
			return nil, fmt.Errorf("winres: resource %d/%d twice", res[i].Type, res[i].ID)
		}
	}
	var types []uint16
	byType := map[uint16][]Resource{}
	for _, r := range res {
		if len(byType[r.Type]) == 0 {
			types = append(types, r.Type)
		}
		byType[r.Type] = append(byType[r.Type], r)
	}

	// Layout: root directory, one directory per type, one per resource
	// (holding its single language), the data entries, then the data.
	const dirHeader, dirEntry, dataEntry = 16, 8, 16
	rootSize := dirHeader + dirEntry*len(types)
	typeDirs := make(map[uint16]int)
	off := rootSize
	for _, t := range types {
		typeDirs[t] = off
		off += dirHeader + dirEntry*len(byType[t])
	}
	nameDirs := make([]int, len(res))
	for i := range res {
		nameDirs[i] = off
		off += dirHeader + dirEntry
	}
	dataEntries := make([]int, len(res))
	for i := range res {
		dataEntries[i] = off
		off += dataEntry
	}
	dataAt := make([]int, len(res))
	for i, r := range res {
		off = align(off, 8)
		dataAt[i] = off
		off += len(r.Data)
	}
	sec := make([]byte, align(off, 8))
	le := binary.LittleEndian
	dir := func(at, entries int) { le.PutUint16(sec[at+14:], uint16(entries)) } // ID entries only
	entry := func(at int, id uint16, target int, subdir bool) {
		le.PutUint32(sec[at:], uint32(id))
		v := uint32(target)
		if subdir {
			v |= 0x80000000
		}
		le.PutUint32(sec[at+4:], v)
	}

	dir(0, len(types))
	for i, t := range types {
		entry(dirHeader+dirEntry*i, t, typeDirs[t], true)
	}
	idx := 0
	var relocs []int
	for _, t := range types {
		dir(typeDirs[t], len(byType[t]))
		for j, r := range byType[t] {
			entry(typeDirs[t]+dirHeader+dirEntry*j, r.ID, nameDirs[idx], true)
			dir(nameDirs[idx], 1)
			entry(nameDirs[idx]+dirHeader, langEnUS, dataEntries[idx], false)
			de := dataEntries[idx]
			le.PutUint32(sec[de:], uint32(dataAt[idx])) // made an address by the relocation
			le.PutUint32(sec[de+4:], uint32(len(r.Data)))
			relocs = append(relocs, de)
			copy(sec[dataAt[idx]:], r.Data)
			idx++
		}
	}

	// COFF: file header, one section header, the section, its
	// relocations, then a symbol table with the section's symbol.
	const fileHeader, sectionHeader, relocSize, symbolSize = 20, 40, 10, 18
	secAt := fileHeader + sectionHeader
	relocAt := secAt + len(sec)
	symAt := relocAt + relocSize*len(relocs)
	out := make([]byte, symAt+symbolSize+4)
	le.PutUint16(out[0:], m.machine)
	le.PutUint16(out[2:], 1) // sections
	le.PutUint32(out[8:], uint32(symAt))
	le.PutUint32(out[12:], 1) // symbols
	sh := out[fileHeader:]
	copy(sh[0:8], ".rsrc")
	le.PutUint32(sh[16:], uint32(len(sec)))
	le.PutUint32(sh[20:], uint32(secAt))
	le.PutUint32(sh[24:], uint32(relocAt))
	le.PutUint16(sh[32:], uint16(len(relocs)))
	le.PutUint32(sh[36:], 0x40000040) // initialized data, readable
	copy(out[secAt:], sec)
	for i, at := range relocs {
		r := out[relocAt+relocSize*i:]
		le.PutUint32(r[0:], uint32(at))
		le.PutUint32(r[4:], 0) // the section's symbol
		le.PutUint16(r[8:], m.reloc)
	}
	sym := out[symAt:]
	copy(sym[0:8], ".rsrc")
	le.PutUint16(sym[12:], 1)               // section number
	sym[16] = 3                             // static
	le.PutUint32(out[symAt+symbolSize:], 4) // empty string table
	return out, nil
}

func align(n, a int) int { return (n + a - 1) / a * a }

// VersionInfo is what a program's Properties > Details shows.
type VersionInfo struct {
	Version     string // X.Y.Z
	ProductName string
	Description string
	Company     string
	Copyright   string
	FileName    string
}

// Data builds the VS_VERSIONINFO resource.
func (v VersionInfo) Data() ([]byte, error) {
	parts := strings.Split(v.Version, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("winres: version %q is not X.Y.Z", v.Version)
	}
	var n [4]uint16
	for i, p := range parts {
		x, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("winres: version %q: %w", v.Version, err)
		}
		n[i] = uint16(x)
	}
	le := binary.LittleEndian
	fixed := make([]byte, 52)
	le.PutUint32(fixed[0:], 0xFEEF04BD)
	le.PutUint32(fixed[4:], 0x00010000)
	ms, ls := uint32(n[0])<<16|uint32(n[1]), uint32(n[2])<<16|uint32(n[3])
	le.PutUint32(fixed[8:], ms)
	le.PutUint32(fixed[12:], ls)
	le.PutUint32(fixed[16:], ms)
	le.PutUint32(fixed[20:], ls)
	le.PutUint32(fixed[24:], 0x3F)    // flags mask
	le.PutUint32(fixed[32:], 0x40004) // VOS_NT_WINDOWS32
	le.PutUint32(fixed[36:], 1)       // VFT_APP

	var strs [][]byte
	for _, kv := range [][2]string{
		{"CompanyName", v.Company},
		{"FileDescription", v.Description},
		{"FileVersion", v.Version},
		{"InternalName", strings.TrimSuffix(v.FileName, ".exe")},
		{"LegalCopyright", v.Copyright},
		{"OriginalFilename", v.FileName},
		{"ProductName", v.ProductName},
		{"ProductVersion", v.Version},
	} {
		if kv[1] == "" {
			continue
		}
		val := wstr(kv[1])
		strs = append(strs, node(kv[0], 1, len(val)/2, val, nil))
	}
	table := node("040904B0", 1, 0, nil, strs)
	sfi := node("StringFileInfo", 1, 0, nil, [][]byte{table})
	trans := []byte{0x09, 0x04, 0xB0, 0x04} // en-US, Unicode
	vfi := node("VarFileInfo", 1, 0, nil, [][]byte{node("Translation", 0, len(trans), trans, nil)})
	return node("VS_VERSION_INFO", 0, len(fixed), fixed, [][]byte{sfi, vfi}), nil
}

// node builds one block of a version resource: length, value length, type,
// key, padding, value, padding, children.
func node(key string, typ uint16, valueLen int, value []byte, children [][]byte) []byte {
	b := make([]byte, 6)
	b = append(b, wstr(key)...)
	b = pad4(b)
	b = append(b, value...)
	for _, c := range children {
		b = pad4(b)
		b = append(b, c...)
	}
	le := binary.LittleEndian
	le.PutUint16(b[0:], uint16(len(b)))
	le.PutUint16(b[2:], uint16(valueLen))
	le.PutUint16(b[4:], typ)
	return b
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// wstr is s as NUL-terminated UTF-16LE.
func wstr(s string) []byte {
	u := append(utf16.Encode([]rune(s)), 0)
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// Manifest is the application manifest: runs as the user who starts it,
// declares Windows 10 and 11, per-monitor DPI awareness, the current
// common controls, and long paths.
func Manifest(name, version string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="` + name + `" version="` + version + `.0" processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
`)
}
