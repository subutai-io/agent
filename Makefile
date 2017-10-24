APP=subutai
CC=go
VERSION=$(shell git describe --tags)
GIT_BRANCH=-$(shell git rev-parse --abbrev-ref HEAD | grep -iv head)
ifeq (${GOPATH}, )
	GOPATH=${HOME}/go
endif
LDFLAGS=-ldflags "-r /snap/subutai-dev/current/lib -w -s -X main.version=${VERSION}${GIT_BRANCH} -X github.com/subutai-io/agent/config.version=${VERSION}${GIT_BRANCH}"

all:
	@if [ ! -d "$(GOPATH)/src/github.com/subutai-io/agent" ]; then mkdir -p $(GOPATH)/src/github.com/subutai-io/; ln -s $(shell pwd) $(GOPATH)/src/github.com/subutai-io/agent; fi
	$(CC) get -d
	$(CC) build ${LDFLAGS} -o $(APP)
snapcraft:
	$(eval export GOPATH=$(shell pwd)/../go)
	$(eval export GOBIN=$(shell pwd)/../go/bin)
	@if [ ! -d "$(GOPATH)/src/github.com/subutai-io/agent" ]; then mkdir -p $(GOPATH)/src/github.com/subutai-io/; ln -s $(shell pwd) $(GOPATH)/src/github.com/subutai-io/agent; fi
	$(CC) get -d
	$(CC) build ${LDFLAGS} -o $(APP)
install: 
	@mkdir -p $(DESTDIR)/bin
	@cp $(APP) $(DESTDIR)/bin
