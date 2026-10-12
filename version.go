package main

import "runtime/debug"

// develVersion is reported when the binary carries no usable module
// version: built with go run, outside a git checkout (e.g. from a source
// tarball), or by a toolchain that recorded no build info.
const develVersion = "devel"

// version returns the mailseck version recorded in the binary's build
// info. The Go toolchain stamps it from VCS at build time (the release tag,
// a pseudo-version, or either with "+dirty"), so no version number is kept
// anywhere in the source.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return versionFrom(nil)
	}
	return versionFrom(info)
}

// versionFrom extracts the main module version from info, falling back to
// develVersion when info is nil or carries no real version. Any other value,
// pseudo-versions and "+dirty" builds included, is returned as recorded.
func versionFrom(info *debug.BuildInfo) string {
	if info == nil || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return develVersion
	}
	return info.Main.Version
}
