GOPATH := $(shell go env GOPATH)
GODEP_BIN := $(GOPATH)/bin/dep
GOLINT := $(GOPATH)/bin/golint
BINARY_NAME := subutai

VERSION=$(shell git describe --tags)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD | grep -iv head)
ifneq (${GIT_BRANCH}, )
	VERSION:=$(VERSION)-$(GIT_BRANCH)
endif

packages = $$(go list ./... | egrep -v '/vendor/')
files = $$(find . -name '*.go' | egrep -v '/vendor/')

.PHONY: all
all: vet test build

$(GODEP):
	go get -u github.com/golang/dep/cmd/dep

#Gopkg.toml: $(GODEP)
#	$(GODEP_BIN) init

vendor:         ## Vendor the packages using dep
	@echo "skip"
#vendor: $(GODEP) Gopkg.toml Gopkg.lock
#	@ echo "No vendor dir found. Fetching dependencies now..."
#	GOPATH=$(GOPATH):. $(GODEP_BIN) ensure

version:
	@ echo $(VERSION)

build:          ## Build the binary
build: vendor
	test $(BINARY_NAME)
	go build -o $(BINARY_NAME) -ldflags "-X main.version=$(VERSION)"

test: vendor
	go test -race $(packages)

vet:            ## Run go vet
vet: vendor
	go tool vet -printfuncs=Debug,Debugf,Debugln,Info,Infof,Infoln,Error,Errorf,Errorln $(files)

lint:           ## Run go lint
lint: vendor $(GOLINT)
	$(GOLINT) -set_exit_status $(packages)
$(GOLINT):
	go get -u github.com/golang/lint/golint

clean:
	test $(BINARY_NAME)
	rm -f $(BINARY_NAME)

help:           ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
