BINARY := mailseck
PREFIX ?= /usr/local

# MAX_LINE is the portfolio's column limit for Go source, in characters.
MAX_LINE := 120

# PLATFORMS lists the GOOS/GOARCH pairs make dist builds release binaries for.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# RELEASE_TAG matches a release tag: vMAJOR.MINOR.PATCH, digits only, so
# pre-release tags such as v1.3.0-rc1 are refused.
RELEASE_TAG := ^v[0-9]+\.[0-9]+\.[0-9]+$$

.PHONY: build check test test-integration lint fmt-check vet line-length dist clean install

build:
	go build -o $(BINARY) .

# check is the single delivery gate: every target it runs must pass.
check: fmt-check vet line-length test

test:
	go test -race ./...

test-integration:
	go test -tags integration ./...

lint: fmt-check vet line-length

# fmt-check fails loudly when gofmt is missing: an absent tool prints
# nothing on stdout, which would otherwise read as "nothing to format".
fmt-check:
	@command -v gofmt >/dev/null 2>&1 || { echo "fmt-check: gofmt not found in PATH" >&2; exit 1; }
	@echo "gofmt -l ."
	@out="$$(gofmt -l .)" || exit 1; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; \
		echo "$$out"; \
		exit 1; \
	fi

vet:
	go vet ./...

# line-length counts characters, not bytes, without trusting awk's
# length(): BSD awk and mawk count bytes whatever the locale. Under
# LC_ALL=C every byte is one unit, so deleting the UTF-8 continuation
# bytes (0x80-0xBF) leaves exactly one byte per character. Go source is
# UTF-8 by definition, and a tab is one byte, so it counts as one.
line-length:
	@echo "line-length: at most $(MAX_LINE) characters per line in *.go"
	@LC_ALL=C find . -name .git -prune -o -type f -name '*.go' -exec awk -v max=$(MAX_LINE) ' \
		{ line = $$0; gsub(/[\200-\277]/, "", line) } \
		length(line) > max { printf "%s:%d: %d characters (max %d)\n", FILENAME, FNR, length(line), max; bad = 1 } \
		END { exit bad }' {} + || { echo "line-length: lines above $(MAX_LINE) characters" >&2; exit 1; }

# dist builds the release binaries and bin/SHA256SUMS for the release tag
# at HEAD. It refuses to run off a release commit (HEAD not exactly at one
# vMAJOR.MINOR.PATCH tag, or a working tree with any change or untracked
# file), and it confirms each binary's embedded module version is exactly
# that tag, so no pseudo-version or +dirty build is ever shipped. The
# version comes from the Go toolchain's VCS stamping; nothing is injected
# with -ldflags -X. Tagging, pushing and publishing stay manual.
dist: check
	@set -e; \
	tags="$$(git tag --points-at HEAD)"; \
	count="$$(printf '%s\n' "$$tags" | grep -cE '$(RELEASE_TAG)' || true)"; \
	if [ "$$count" != 1 ]; then \
		echo "dist: HEAD must be exactly at one release tag (vMAJOR.MINOR.PATCH), found: $${tags:-none}" >&2; \
		exit 1; \
	fi; \
	tag="$$(printf '%s\n' "$$tags" | grep -E '$(RELEASE_TAG)')"; \
	changes="$$(git status --porcelain)"; \
	if [ -n "$$changes" ]; then \
		echo "dist: working tree is not clean (untracked files count):" >&2; \
		echo "$$changes" >&2; \
		exit 1; \
	fi; \
	if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"; \
	elif command -v shasum >/dev/null 2>&1; then sum="shasum -a 256"; \
	else echo "dist: neither sha256sum nor shasum found in PATH" >&2; exit 1; fi; \
	rm -rf bin; \
	mkdir bin; \
	trap 'rm -rf bin' EXIT; \
	for platform in $(PLATFORMS); do \
		os="$${platform%/*}"; \
		arch="$${platform#*/}"; \
		out="bin/$(BINARY)-$$tag-$$os-$$arch"; \
		if [ "$$os" = windows ]; then out="$$out.exe"; fi; \
		echo "build $$out"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -ldflags="-s -w" -o "$$out" .; \
		got="$$(go version -m "$$out" | awk '$$1 == "mod" { print $$3 }')"; \
		if [ "$$got" != "$$tag" ]; then \
			echo "dist: $$out embeds module version '$$got', want '$$tag'" >&2; \
			exit 1; \
		fi; \
	done; \
	(cd bin && $$sum $(BINARY)-* > SHA256SUMS); \
	trap - EXIT; \
	echo "dist: $$tag binaries and SHA256SUMS written to bin/"

clean:
	rm -f $(BINARY)

install:
	go install .
