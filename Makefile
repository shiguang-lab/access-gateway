.PHONY: build test run local-up local-smoke local-down local-e2e local-persistence-test

build:
	CGO_ENABLED=0 go build -trimpath -o bin/access-gateway ./cmd/access-gateway

test:
	go test ./...

run:
	go run ./cmd/access-gateway

local-up:
	./local/stack.sh up

local-smoke:
	./local/stack.sh smoke

local-down:
	./local/stack.sh down

local-e2e:
	./local/stack.sh e2e

local-persistence-test:
	./local/run-persistence-tests.sh
