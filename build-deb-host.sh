#!/bin/bash
set -xe

BUILD_ARTIFACTS_DIR="debian"
BINARY_NAME=subutai

VERSION=$(shell git describe --tags)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD | grep -iv head)
ifneq (${GIT_BRANCH}, )
	VERSION:=$(VERSION)-$(GIT_BRANCH)
endif


# check all the required environment variables are supplied
[ -z "$DEB_PACKAGE_NAME" ] && echo "Need to set DEB_PACKAGE_NAME" && exit 1;
[ -z "$DEB_PACKAGE_DESCRIPTION" ] && echo "Need to set DEB_PACKAGE_DESCRIPTION" && exit 1;

if which go; then
    make build
    echo "Binary built. Building DEB now."
else
    echo "golang not installed or not reachable"
    exit 1
fi

mkdir -p $BUILD_ARTIFACTS_DIR && cp $BINARY_NAME $BUILD_ARTIFACTS_DIR
if which fpm; then
    fpm --output-type deb \
      --input-type dir --chdir /$BUILD_ARTIFACTS_DIR \
      --prefix /usr/bin --name $BINARY_NAME \
      --version $VERSION \
      --description '${DEB_PACKAGE_DESCRIPTION}' \
      -p ${DEB_PACKAGE_NAME}-${VERSION}.deb \
      $BINARY_NAME && cp *.deb /$BUILD_ARTIFACTS_DIR/
    rm -f $BUILD_ARTIFACTS_DIR/$BINARY_NAME
else
    echo "fpm not installed or not reachable"
    exit 1
fi
