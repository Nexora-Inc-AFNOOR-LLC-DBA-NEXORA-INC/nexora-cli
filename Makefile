.PHONY: build test lint security clean tidy fmt

BINARY := nexora
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/version.Version=$(VERSION) \
	-X github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/version.Commit=$(COMMIT) \
	-X github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/version.BuildDate=$(DATE)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./main.go

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run

security:
	gosec ./...
	govulncheck ./...

fmt:
	gofmt -w .
	goimports -w .

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) coverage.out

vet:
	go vet ./...

all: tidy fmt vet test lint security build
