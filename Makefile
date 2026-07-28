BINARY := mailseck
PREFIX ?= /usr/local

.PHONY: build test test-integration lint clean install

build:
	go build -o $(BINARY) .

test:
	go test ./...

test-integration:
	go test -tags integration ./...

lint:
	go vet ./...
	@fmtout="$$(gofmt -l .)"; \
	if [ -n "$$fmtout" ]; then \
		echo "gofmt needs to be run on:"; \
		echo "$$fmtout"; \
		exit 1; \
	fi

clean:
	rm -f $(BINARY)

install:
	go install .