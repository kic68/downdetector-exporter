BINARY_NAME     := downdetector-exporter
VERSION         := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE_NAME      := $(BINARY_NAME):$(VERSION)
LOCAL_BIN       := $(CURDIR)/bin
GOLANGCI_LINT   := $(LOCAL_BIN)/golangci-lint

GOLANGCI_LINT_VERSION := 2.14.0
GOLANGCI_LINT_OS      := $(shell go env GOOS)
GOLANGCI_LINT_ARCH    := $(shell go env GOARCH)
GOLANGCI_LINT_ARCHIVE := golangci-lint-$(GOLANGCI_LINT_VERSION)-$(GOLANGCI_LINT_OS)-$(GOLANGCI_LINT_ARCH)
GOLANGCI_LINT_URL     := https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/$(GOLANGCI_LINT_ARCHIVE).tar.gz

# Use docker if it's present and actually working (e.g. not just the podman-docker
# shim pointing at a dead podman socket), otherwise fall back to podman.
CONTAINER_ENGINE := $(shell \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		echo docker; \
	elif command -v podman >/dev/null 2>&1; then \
		echo podman; \
	elif command -v docker >/dev/null 2>&1; then \
		echo docker; \
	fi)

.PHONY: all
all: lint test build

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run

# Downloads the golangci-lint release archive directly and extracts the binary into ./bin.
# See https://github.com/golangci/golangci-lint/releases
$(GOLANGCI_LINT):
	mkdir -p $(LOCAL_BIN)
	tmp_dir=$$(mktemp -d); \
	curl -sfL $(GOLANGCI_LINT_URL) | tar -xz -C $$tmp_dir; \
	cp $$tmp_dir/$(GOLANGCI_LINT_ARCHIVE)/golangci-lint $(GOLANGCI_LINT); \
	rm -rf $$tmp_dir

.PHONY: container-build
container-build:
	@if [ -z "$(CONTAINER_ENGINE)" ]; then \
		echo "neither docker nor podman found in PATH"; \
		exit 1; \
	fi
	$(CONTAINER_ENGINE) build --build-arg VERSION=$(VERSION) --tag $(IMAGE_NAME) .

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
