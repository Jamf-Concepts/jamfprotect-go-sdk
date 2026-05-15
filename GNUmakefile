default: fmt lint build

build:
	go build -v ./...

lint:
	golangci-lint run

generate:
	cd tools/generate; go run .
	cd tools; go generate ./...

fix:
	go fix ./...
	cd tools/generate; go fix ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -count=1 -timeout=120s ./...

testacc:
	JAMFPROTECT_ACC=1 go test -v -cover -count=1 -timeout 120m -p=1 ./...

vet:
	go vet ./...

.PHONY: fmt fix lint test testacc build generate vet
