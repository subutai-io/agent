APP=subutai
CC=go
CP=cp
VERSION=4.0.4-SNAPSHOT
LDFLAGS=-ldflags "-r /snap/subutai/current/lib -w -s -X main.Version=${VERSION}"

all:
	$(CC) build ${LDFLAGS} -o $(APP)
install: 
	$(CP) $(APP) $(DESTDIR)
