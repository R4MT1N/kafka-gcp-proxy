.DEFAULT_GOAL := build

.PHONY: clean build test fmt check lint-code lint-fix docker.build tag release

ROOT_DIR     = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

BINARY       ?= kafka-gcp-proxy
SOURCES       = $(shell find . -name '*.go' | grep -v /vendor/)
VERSION      ?= $(shell git describe --tags --always --dirty)
GOPKGS        = $(shell go list ./... | grep -v /vendor/)
BUILD_FLAGS  ?=
LDFLAGS      ?= -X github.com/R4MT1N/kafka-gcp-proxy/config.Version=$(VERSION) -w -s
TAG          ?= "v0.0.1"

GOLANGCI_LINT = go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.63.4

default: build

test.race:
	go test -v -race -count=1 -mod=vendor `go list ./...`

test:
	go test -v -count=1 -mod=vendor `go list ./...`

fmt:
	go fmt $(GOPKGS)

check: lint-code
	go vet $(GOPKGS)

lint-code:
	$(GOLANGCI_LINT) run --timeout 5m

lint-fix:
	$(GOLANGCI_LINT) run --fix

build: build/$(BINARY)

build/$(BINARY): $(SOURCES)
	CGO_ENABLED=0 go build -mod=vendor -o build/$(BINARY) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" .

docker.build:
	docker build --build-arg VERSION=$(VERSION) -t local/kafka-gcp-proxy .

tag:
	git tag $(TAG)

release: clean
	git push origin $(TAG)

clean:
	rm -rf $(ROOT_DIR)/build
