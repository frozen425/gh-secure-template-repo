BINARY := bin/gh-secure
MODULE := gh-secure-template-repo

.PHONY: build test vet lint clean run help

## build: Compile the binary
build:
	@mkdir -p bin
	go build -o $(BINARY) ./

## test: Run all tests
test:
	go test ./... -v -count=1

## vet: Run go vet
vet:
	go vet ./...

## lint: Run vet + build (add golangci-lint here if available)
lint: vet build

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## run: Build and run an assess scan (requires OWNER and NAME, e.g. make run OWNER=heelerai NAME=skully-poc)
run: build
	./$(BINARY) --owner $(OWNER) --name $(NAME)

## login: Authenticate via OAuth device flow (requires CLIENT_ID)
login: build
	./$(BINARY) --login --client-id $(CLIENT_ID)

## logout: Clear cached auth token
logout: build
	./$(BINARY) --logout

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
