default: fmt lint build

build:
	go build -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -count=1 -timeout=120s ./...

vet:
	go vet ./...

.PHONY: fmt lint test build generate vet
