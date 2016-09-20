APP=subutai
VERSION=4.0.4-SNAPSHOT
LDFLAGS=-ldflags "-r /snap/subutai/current/lib -w -s -X main.Version=${VERSION}"

all:
	@go build ${LDFLAGS} -o $(APP)
install: 
	@mkdir -p $(DESTDIR)/bin
	@cp $(APP) $(DESTDIR)/bin
