APP=subutai
CC=go
VERSION=$(shell git describe --abbrev=0 --tags)
ifeq (${GIT_BRANCH}, )
	GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD | grep -iv head)
endif
ifneq (${GIT_BRANCH}, )
	VERSION=$(shell git describe --abbrev=0 --tags | awk -F'.' '{print $$1"."$$2"."$$3+1}')-SNAPSHOT
endif
COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags "-r /snap/subutai-dev/current/lib -w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X github.com/subutai-io/agent/config.version=$(VERSION)"

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
