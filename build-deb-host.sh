#!/bin/bash
set -xe

BUILD_ARTIFACTS_DIR="artifacts"
VERSION=$(git describe --tags)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD | grep -iv head)
ifneq (${GIT_BRANCH}, )
	VERSION:=$(VERSION)-$(GIT_BRANCH)
endif


# check all the required environment variables are supplied
[ -z "$BINARY_NAME" ] && echo "Need to set BINARY_NAME" && exit 1;
[ -z "$DEB_PACKAGE_NAME" ] && echo "Need to set DEB_PACKAGE_NAME" && exit 1;
[ -z "$DEB_PACKAGE_DESCRIPTION" ] && echo "Need to set DEB_PACKAGE_DESCRIPTION" && exit 1;

if which go; then
    make build BINARY_NAME=${BINARY_NAME}
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
      --version $VERSION_STRING \
      --description '${DEB_PACKAGE_DESCRIPTION}' \
      -p ${DEB_PACKAGE_NAME}-${VERSION_STRING}.deb \
      $BINARY_NAME && cp *.deb /$BUILD_ARTIFACTS_DIR/
    rm -f $BUILD_ARTIFACTS_DIR/$BINARY_NAME
else
    echo "fpm not installed or not reachable"
    exit 1
fi
