BINARY := mailseck
PREFIX ?= /usr/local

# MAX_LINE is the portfolio's column limit for Go source, in characters.
MAX_LINE := 120

.PHONY: build check test test-integration lint fmt-check vet line-length clean install

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

clean:
	rm -f $(BINARY)

install:
	go install .
