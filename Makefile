GO       ?= go
BIN      := dns2ipset
PKG      := ./cmd/dns2ipset
LDFLAGS  := -s -w
BPF_DIR  := internal/bpf
VERSION  ?= $(shell ./packaging/git-version.sh)

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

# Try to generate vmlinux.h from the running kernel's BTF. If bpftool is
# missing or refuses to parse the kernel's BTF (common on CI runners and
# WSL2 where the bpftool/kernel versions don't agree), fall back to the
# committed minimal shim. CO-RE resolves real field offsets at load time,
# so the shim is functionally equivalent for our purposes.
$(BPF_DIR)/c/headers/vmlinux.h: $(BPF_DIR)/c/headers/vmlinux.h.shim
	@mkdir -p $(BPF_DIR)/c/headers
	@if command -v bpftool >/dev/null 2>&1 && [ -r /sys/kernel/btf/vmlinux ] \
	    && bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp 2>/dev/null; then \
	    mv $@.tmp $@; \
	    echo "vmlinux.h: generated from /sys/kernel/btf/vmlinux"; \
	else \
	    rm -f $@.tmp; \
	    cp $(BPF_DIR)/c/headers/vmlinux.h.shim $@; \
	    echo "vmlinux.h: bpftool unavailable or refused BTF; using committed shim"; \
	fi

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
