APP=subutai
CC=go
CONFIG=agent.gcfg
VERSION=$(shell grep version ${CONFIG} | awk '{print $$3}')
BRANCH=$(shell grep branch ${CONFIG} | awk '{print $$3}')
ifneq (${BRANCH}, )
	VERSION:=${VERSION}-SNAPSHOT
endif
COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags "-r /apps/subutai/current/lib -w -s -X main.version=${VERSION} -X main.commit=${COMMIT}"

all:
	@echo ${BRANCH}
	$(CC) build ${LDFLAGS} -o $(APP)
install: 
	@mkdir -p $(DESTDIR)/bin
	@cp $(APP) $(DESTDIR)/bin
