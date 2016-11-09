APP=subutai
CC=go
CONFIG=agent.gcfg
VERSION=$(shell grep version ${CONFIG} | awk '{print $$3}')
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
ifneq (${BRANCH}, )
	VERSION:=${VERSION}-SNAPSHOT
endif
COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags "-r /apps/subutai/current/lib -w -s -X main.version=${VERSION} -X main.commit=${COMMIT}"

all:
	@sed 's/branch =.*/branch = ${BRANCH}/g' -i ${CONFIG}
	$(CC) get
	$(CC) build ${LDFLAGS} -o $(APP)
install: 
	@mkdir -p $(DESTDIR)/bin
	@cp $(APP) $(DESTDIR)/bin
