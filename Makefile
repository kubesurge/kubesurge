BINARY    := kubesurge
MODULE    := github.com/kubesurge/kubesurge
BUILD_DIR := ./bin

# Docker image for the diagnostic payload (the container injected into pods)
# Override REGISTRY to push to your own registry:
#   make docker-build docker-push REGISTRY=myacr.azurecr.io/kubesurge
REGISTRY    ?= ghcr.io/kubesurge
DEBUG_IMAGE := $(REGISTRY)/debugpod
DEBUG_TAG   ?= latest

# Kind cluster name — matches TurnkeyIDP's kind cluster
KIND_CLUSTER ?= idp-dev-cluster

# go build flags:
#   -trimpath   removes local file paths from stack traces (security / reproducibility)
#   -ldflags    injects version info at link time without recompiling
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -trimpath -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: build install tidy lint test docker-build docker-push kind-load clean help

## build: Compile the kubesurge binary into ./bin/
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) .
	@echo "✅ Built: $(BUILD_DIR)/$(BINARY)"

## install: Install kubesurge to /usr/local/bin (may require sudo)
install: build
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "✅ Installed to /usr/local/bin/$(BINARY)"

## tidy: Download and tidy go.mod / go.sum
tidy:
	go mod tidy
	@echo "✅ go.mod and go.sum are tidy"

## docker-build: Build the kubesurge-debugpod image locally
docker-build:
	docker build \
		-f Dockerfile.debugpod \
		-t $(DEBUG_IMAGE):$(DEBUG_TAG) \
		--label "org.opencontainers.image.revision=$$(git rev-parse --short HEAD 2>/dev/null || echo dev)" \
		.
	@echo "✅ Built image: $(DEBUG_IMAGE):$(DEBUG_TAG)"

## docker-push: Push the debugpod image to the registry
docker-push: docker-build
	docker push $(DEBUG_IMAGE):$(DEBUG_TAG)
	@echo "✅ Pushed: $(DEBUG_IMAGE):$(DEBUG_TAG)"

## kind-load: Load the debugpod image directly into the kind cluster (no registry needed)
## Usage: make kind-load REGISTRY=localhost KIND_CLUSTER=idp-dev-cluster
kind-load: docker-build
	kind load docker-image $(DEBUG_IMAGE):$(DEBUG_TAG) --name $(KIND_CLUSTER)
	@echo "✅ Loaded $(DEBUG_IMAGE):$(DEBUG_TAG) into kind cluster '$(KIND_CLUSTER)'"
	@echo "   Use: --image $(DEBUG_IMAGE):$(DEBUG_TAG) --image-pull-policy IfNotPresent"

## lint: Run golangci-lint (install: brew install golangci-lint)
lint:
	golangci-lint run ./...

## test: Run all unit tests
test:
	go test -v -race ./...

## clean: Remove build artefacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "✅ Cleaned"

## help: Print this help message
help:
	@echo ""
	@echo "  kubesurge Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /    /'
	@echo ""
