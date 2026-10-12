package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionFrom(t *testing.T) {
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{name: "build info absent", info: nil, want: "devel"},
		{name: "empty version", info: &debug.BuildInfo{}, want: "devel"},
		{name: "go run or no VCS", info: buildInfo("(devel)"), want: "devel"},
		{name: "release tag", info: buildInfo("v1.2.0"), want: "v1.2.0"},
		{
			name: "pseudo-version",
			info: buildInfo("v1.2.1-0.20261012154500-9a9a64a986a3"),
			want: "v1.2.1-0.20261012154500-9a9a64a986a3",
		},
		{name: "dirty tree", info: buildInfo("v1.2.0+dirty"), want: "v1.2.0+dirty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFrom(tt.info); got != tt.want {
				t.Errorf("versionFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionIsNeverEmpty(t *testing.T) {
	if version() == "" {
		t.Error("version() = \"\", want a non-empty version")
	}
}

func buildInfo(mainVersion string) *debug.BuildInfo {
	return &debug.BuildInfo{Main: debug.Module{Path: "github.com/mentesan/mailseck", Version: mainVersion}}
}
