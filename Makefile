GO       ?= go
BIN      := dns2ipset
PKG      := ./cmd/dns2ipset
LDFLAGS  := -s -w
BPF_DIR  := internal/bpf
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)

.PHONY: build vet test test-integration generate bpf package clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./...

# Regenerate vmlinux.h and run bpf2go.
generate: $(BPF_DIR)/c/headers/vmlinux.h
	$(GO) generate ./...

$(BPF_DIR)/c/headers/vmlinux.h:
	mkdir -p $(BPF_DIR)/c/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build a .deb package via nfpm. Requires `make build` to have produced
# ./dns2ipset. VERSION is exported for nfpm.yaml's ${VERSION} expansion.
package: build
	VERSION=$(VERSION) $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@latest pkg \
		--config packaging/nfpm.yaml \
		--target dns2ipset_$(VERSION)_amd64.deb \
		--packager deb

clean:
	rm -f $(BIN)
	rm -f $(BPF_DIR)/*_bpfel.go $(BPF_DIR)/*_bpfeb.go
	rm -f $(BPF_DIR)/*_bpfel.o $(BPF_DIR)/*_bpfeb.o
	rm -f $(BPF_DIR)/c/*.bpf.o
	rm -f dns2ipset_*_amd64.deb
