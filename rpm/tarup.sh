#!/bin/sh

set -euxv

CWD="$(cd -- "$(dirname -- "$(command -v -- "${0}")")"; pwd -P)"
mkdir "${CWD}/SOURCES"
if [ -e "${CWD}/SOURCES/darling.tar.gz" ]; then
  rm "${CWD}/SOURCES/darling.tar.gz"
fi
if [ -e "${CWD}/SOURCES/darling-macho-deps.tar.gz" ]; then
  rm "${CWD}/SOURCES/darling-macho-deps.tar.gz"
fi
tar --transform "s|^\.|darling|S" -caf "${CWD}/SOURCES/darling.tar.gz" -C "${CWD}/.." --exclude=.git --exclude SOURCES --exclude SRPMS --exclude RPMS --exclude BUILD .
tar --transform "s|^\.|darling-macho-deps|S" -caf "${CWD}/SOURCES/darling-macho-deps.tar.gz" -C "${CWD}/../tools/rpm" .
