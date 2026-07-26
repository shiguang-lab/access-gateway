.PHONY: build test run

build:
	CGO_ENABLED=0 go build -trimpath -o bin/access-gateway ./cmd/access-gateway

test:
	go test ./...

run:
	go run ./cmd/access-gateway
