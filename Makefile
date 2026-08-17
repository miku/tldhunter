BINARY := tldhunt
GO     := go
GOFLAGS := -trimpath -ldflags='-s -w'

.PHONY: all build fmt vet clean update-tld

all: build

build: $(BINARY)

# tlds.txt is a prerequisite because it is embedded into the binary.
$(BINARY): tldhunt.go tlds.txt
	$(GO) build $(GOFLAGS) -o $@ tldhunt.go

fmt:
	gofmt -w tldhunt.go

vet:
	$(GO) vet ./tldhunt.go

# Refresh tlds.txt from IANA, then rebuild so the new list gets embedded.
update-tld: $(BINARY)
	./$(BINARY) --update-tld
	$(MAKE) build

clean:
	rm -f $(BINARY)
