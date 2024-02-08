GIT_REPO:=github.com/mjdusa/go-self-signed-cert-http-server
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD)
GIT_COMMIT:=$(shell git log --pretty=format:'%H' -n 1)
GIT_TAGS:=$(shell git describe --tags)
#
BUILD_TS:=$(shell date -u "+%Y-%m-%dT%TZ")
BUILD_DIR:=dist
APP_NAME:=example
APP_VERSION:=$(shell cat .version)
LINTER_REPORT:=$(BUILD_DIR)/golangci-lint-report.xml
#
GO_VERSION:=$(shell go version | sed -r 's/go version go(.*)\ .*/\1/')
GOARCH:=$(shell go env GOARCH)
GOBIN:=${GOPATH}/bin
GOCMD:=go
GOFLAGS=
GOBUILD=$(GOCMD) build
#
clean:
	$(GOCMD) clean --cache

.PHONY: $(BUILD_DIR)
$(BUILD_DIR):
	mkdir -p $@

.PHONY: prebuild
prebuild: $(BUILD_DIR)
	@echo "Running go mod tidy & vendor"
	$(GOCMD) version
	$(GOCMD) env
	$(GOCMD) env -w GOPRIVATE=""
	$(GOCMD) mod tidy && $(GOCMD) mod vendor

.PHONY: golangcilint
golangcilint: prebuild $(BUILD_DIR)
	echo "Running golangci-lint"
	${GOPATH}/bin/golangci-lint --version
	${GOPATH}/bin/golangci-lint run --verbose --config .github/linters/.golangci.yml \
	  --issues-exit-code 0 --out-format=checkstyle > "$(LINTER_REPORT)"
	cat $(LINTER_REPORT)

.PHONY: lint
lint: prebuild golangcilint

.PHONY: test
test:
	$(GOFLAGS) $(GOCMD) test ./...

.PHONY: cover
cover:
	ulimit -a
	$(GOFLAGS) $(GOCMD) test --coverprofile=coverage.out ./...

.PHONY: run
run:
	$(GOFLAGS) $(GOCMD) run cmd/example/main.go

.PHONY: build
build:
	$(GOFLAGS) $(GOBUILD) -o dist/example cmd/example/main.go
