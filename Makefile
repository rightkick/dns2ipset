GO       ?= go
BIN      := dns2ipset
PKG      := ./cmd/dns2ipset
LDFLAGS  := -s -w
BPF_DIR  := internal/bpf

.PHONY: build vet test test-integration generate bpf clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./...

# Regenerate vmlinux.h and run bpf2go.
generate: $(BPF_DIR)/headers/vmlinux.h
	$(GO) generate ./...

$(BPF_DIR)/headers/vmlinux.h:
	mkdir -p $(BPF_DIR)/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(BIN)
	rm -f $(BPF_DIR)/*_bpfel.go $(BPF_DIR)/*_bpfel.o
