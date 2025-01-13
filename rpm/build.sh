#!/bin/sh

set -euxv

mkdir -p ~/rpmbuild/SOURCES

if [ -e /src/rpm/SOURCES/darling.tar.gz ]; then
  ln -sf /src/rpm/SOURCES/darling.tar.gz ~/rpmbuild/SOURCES/
else
  # Preparing tarball
  tar --transform "s|^\.|darling|S" -caf ~/rpmbuild/SOURCES/darling.tar.gz -C /src --exclude .git --exclude SOURCES --exclude=SRPMS --exclude RPMS --exclude BUILD .
fi

if [ -e /src/rpm/SOURCES/darling-macho-deps.tar.gz ]; then
  ln -sf /src/rpm/SOURCES/darling-macho-deps.tar.gz ~/rpmbuild/SOURCES/
else
  tar --transform "s|^\.|darling-macho-deps|S" -caf ~/rpmbuild/SOURCES/darling-macho-deps.tar.gz -C /src/tools/rpm .
fi

if DARLING_COMMIT_DATE="$(git -C /src log -1 --pretty=format:%cs HEAD)"; then
  export DARLING_COMMIT_DATE="$(echo "${DARLING_COMMIT_DATE}" | tr -d -)"
else
  # default to the current date
  export DARLING_COMMIT_DATE="$(date +%Y%m%d)"
fi

rpmbuild -bb /src/rpm/SPECS/darling-macho-deps.spec
sudo rpm -U --force ~/rpmbuild/RPMS/$(uname -m)/darling-macho-deps*.rpm

#spectool -g -R /src/rpm/SPECS/darling.spec
rpmbuild -bb /src/rpm/SPECS/darling.spec
rpmbuild -bb /src/rpm/SPECS/darling-cli-devenv.spec
