# Everyday checks on any system. The MSI is built on Windows with
# scripts/build.ps1.
GO      ?= go
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version.Version=$(VERSION)
PKGS     = $$($(GO) list ./... | grep -v /third_party/)
WINPKGS  = $$(GOOS=windows $(GO) list ./... | grep -v /third_party/)

.PHONY: check vet test build clean

check: vet test build

vet:
	@test -z "$$(gofmt -l cmd internal)" || (echo "gofmt needed:"; gofmt -l cmd internal; exit 1)
	$(GO) vet $(PKGS)
	GOOS=windows GOARCH=amd64 $(GO) vet $(WINPKGS)
	GOOS=windows GOARCH=arm64 $(GO) vet $(WINPKGS)

test:
	$(GO) test -race ./...

# Both programs for both architectures (no MSI).
build:
	@for arch in amd64 arm64; do \
	  GOOS=windows GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS) -H windowsgui" -o build/$$arch/hifaz.exe ./cmd/hifaz && \
	  GOOS=windows GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o build/$$arch/hifaz-service.exe ./cmd/hifaz-service || exit 1; \
	done

clean:
	rm -rf build dist
