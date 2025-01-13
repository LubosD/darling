#disable binary striping, in case this is a problem
%global __os_install_post %{nil}
#Disable debug packages, since these are emulated files mostly
%define debug_package %{nil}
%define commit_date %{getenv:DARLING_COMMIT_DATE}
%if "%{commit_date}" == ""
	%define commit_date 0
%endif

# explicitly ignore all the bogus dependencies that the auto-scanner finds in `/usr/libexec/darling`
#
# note that we *don't* want to simply use `__requires_exclude_from` to exclude `/usr/libexec/darling` from scanning,
# since we *do* want our Mach-O scanner to scan that tree (and there's no way to only exclude paths for some dependency generators; it's all or nothing).
%global __requires_exclude ^(/bin/sed|/bin/sh|/usr/bin/perl|/usr/bin/python2.7|/System/Library/Frameworks/Python.framework/Versions/2.7/bin/python2.7|/usr/bin/python|/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby|/usr/bin/env|/usr/bin/ruby)$

Name:           darling
Version:        0.1.%{commit_date}
Release:        1%{?dist}
Summary:        Darling

Group:          Utility
License:        GPLv3
URL:            https://www.darlinghq.org/
# Use this line for Source0 if there are ever official versions.
# Source0:        https://github.com/darlinghq/darling/archive/%%{version}/%%{name}-%%{version}.tar.gz
Source0:        %{name}.tar.gz

BuildRequires:  cmake clang bison flex glibc-devel(x86-64) glibc-devel(x86-32)
BuildRequires:  fuse-devel systemd-devel
BuildRequires:  cairo-devel freetype-devel(x86-64) fontconfig-devel(x86-64)
BuildRequires:  freetype-devel(x86-32) fontconfig-devel(x86-32) make
BuildRequires:  libjpeg-turbo-devel(x86-64) libtiff-devel(x86-64)
BuildRequires:  libjpeg-turbo-devel(x86-32)
BuildRequires:  libglvnd-devel mesa-libGL-devel mesa-libEGL-devel
BuildRequires:  libxml2-devel elfutils-libelf-devel
BuildRequires:  libbsd-devel
BuildRequires:  ffmpeg-devel pulseaudio-libs-devel openssl-devel giflib-devel
BuildRequires:  libXrandr-devel libXcursor-devel libxkbfile-devel dbus-devel mesa-libGLU-devel
BuildRequires:  vulkan-headers llvm-devel libcap-devel vulkan-loader-devel

Requires: darling-cli darling-python2 darling-ruby darling-perl darling-gui darling-gui-stubs darling-pyobjc

%description
Translation layer for running macOS software on Linux

%package extra
Summary:       Extra components for Darling
Group:         Utility
Requires:      darling darling-jsc darling-cli-extra

%description extra
Extra components for Darling that are not part of a typical ("stock") installation

%package core
Summary:    Darling core components
Group:      Utility
Requires:   xdg-user-dirs

%description core
Core components of Darling

%package system
Summary:    Darling system components
Group:      Utility
Requires:   darling-core

%description system
System components of Darling

%package cli
Summary:    Darling CLI components
Group:      Utility
Requires:   darling-system darling-cli-gui-common darling-cli-python2-common

%description cli
CLI components of Darling

%package ffi
Summary:    libffi for Darling
Group:      Utility
Requires:   darling-core

%description ffi
libffi built for use within Darling

%package cli-gui-common
Summary:    Darling CLI and GUI common components
Group:      Utility
Requires:   darling-system

%description cli-gui-common
Components of Darling that are shared between the CLI and GUI components

%package iokitd
Summary:    Darling IOKit daemon
Group:      Utility
Requires:   darling-system darling-iosurface

%description iokitd
IOKit daemon for Darling

%package cli-devenv-gui-common
Summary:    Darling developer environment and GUI common components
Group:      Utility
Requires:   darling-system

%description cli-devenv-gui-common
Components of Darling that are shared between the developer environment and the GUI components

%package cli-extra
Summary:    Extra Darling CLI components
Group:      Utility
Requires:   darling-cli

%description cli-extra
Non-standard CLI components of Darling

%package gui
Summary:    Darling GUI components
Group:      Utility
Requires:   darling-system darling-cli-devenv-gui-common darling-iokitd darling-cli-gui-common darling-iosurface

%description gui
GUI components of Darling

%package python2
Summary:    Python 2 for Darling
Group:      Utility
Requires:   darling-core darling-cli-python2-common darling-ffi

%description python2
Python 2 (and associated programs) built for use within Darling

%package cli-python2-common
Summary:    Darling CLI and Python 2 common components
Group:      Utility
Requires:   darling-core

%description cli-python2-common
Components of Darling that are shared between the CLI and Python 2 components

%package pyobjc
Summary:    PyObjC for Darling
Group:      Utility
Requires:   darling-gui-stubs darling-python2

%description pyobjc
PyObjC built for use within Darling

%package ruby
Summary:    Ruby for Darling
Group:      Utility
Requires:   darling-core darling-ffi

%description ruby
Ruby built for use within Darling

%package perl
Summary:    Perl for Darling
Group:      Utility
Requires:   darling-core

%description perl
Perl built for use within Darling

%package jsc-webkit-common
Summary:    Darling JavaScriptCore and WebKit common components
Group:      Utility
Requires:   darling-system

%description jsc-webkit-common
Components of Darling that are shared between JavaScriptCore and WebKit

%package jsc
Summary:    JavaScriptCore for Darling
Group:      Utility
Requires:   darling-system darling-jsc-webkit-common

%description jsc
JavaScriptCore built for use within Darling

%package iosurface
Summary:    IOSurface framework for Darling
Group:      Utility
Requires:   darling-system

%description iosurface
IOSurface framework built for use within Darling

%package cli-devenv-gui-stubs-common
Summary:    Darling developer environment and GUI stubs common components
Group:      Utility
Requires:   darling-cli-devenv-gui-common

%description cli-devenv-gui-stubs-common
Components of Darling that are shared between the developer environment and GUI stub components

%package gui-stubs
Summary:    Darling GUI stub components
Group:      Utility
Requires:   darling-gui darling-cli-devenv-gui-stubs-common

%description gui-stubs
GUI stub components of Darling

%prep
%setup -q -n %{name}

%build
%{__mkdir_p} build
cd build
# Release is broken https://github.com/darlinghq/darling/issues/331
#          -DCMAKE_BUILD_TYPE=Release \
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
%{__cmake} -DCMAKE_INSTALL_PREFIX=%{_prefix} \
           -DOpenGL_GL_PREFERENCE=GLVND \
           -DDEBIAN_PACKAGING=ON \
           -DJSC_UNIFIED_BUILD=ON \
           ..
%{make_build}

%install
%if "%{?buildroot}" != "" && "%{?buildroot}" != "/"
%{__rm} -Rf "%{buildroot}"
%{__mkdir_p} "%{dirname:%{buildroot}}"
%endif

cd build

for component in \
    core \
    system \
    cli \
    ffi \
    cli_gui_common \
    iokitd \
    cli_dev_gui_common:cli-devenv-gui-common \
    cli_extra \
    gui \
    python:python2 \
    cli_python_common:cli-python2-common \
    pyobjc \
    ruby \
    perl \
    jsc_webkit_common \
    jsc \
    iosurface \
    cli_dev_gui_stubs_common:cli-devenv-gui-stubs-common \
    gui_stubs
do
    case "${component}" in
        *:*) package="${component#*:}" component="${component%:*}" ;;
        *)   package="$(printf %s "${component}" | tr _ -)" ;;
    esac
    export DESTDIR="tmp/${package}"
    %{__rm} -Rf "${DESTDIR}"
    %{__cmake} -D COMPONENT="${component}" -P cmake_install.cmake
    (
        cd "${DESTDIR}"
        echo "%attr(-, root, root)"
        find * -type d -empty | LC_ALL=C sort | sed -e 's|^|%dir "/|' -e 's|$|"|'
        find * ! -type d | LC_ALL=C sort | sed -e 's|^|"/|' -e 's|$|"|'
    ) >"files.${package}.txt"
    %{__cp} -PRp "${DESTDIR}/." %{?buildroot}/
    %{__rm} -Rf "${DESTDIR}"
done

# pack up a "source" (actually binary) tarball for `darling-cli-devenv`
# NOTE: this is probably not the best approach. fix this if something better comes up.
export DESTDIR=tmp/cli-devenv
%{__rm} -Rf "${DESTDIR}"
%{__cmake} -D COMPONENT=cli_dev -P cmake_install.cmake
%{__tar} --transform "s|^\.|darling-cli-devenv|S" -caf %{_sourcedir}/darling-cli-devenv.tar.gz -C "${DESTDIR}" .
%{__rm} -Rf "${DESTDIR}"

%files

%files extra

%files core -f build/files.core.txt
%attr(-, root, root)
%license LICENSE

%files system -f build/files.system.txt
%files cli -f build/files.cli.txt
%files ffi -f build/files.ffi.txt
%files cli-gui-common -f build/files.cli-gui-common.txt
%files iokitd -f build/files.iokitd.txt
%files cli-devenv-gui-common -f build/files.cli-devenv-gui-common.txt
%files cli-extra -f build/files.cli-extra.txt
%files gui -f build/files.gui.txt
%files python2 -f build/files.python2.txt
%files cli-python2-common -f build/files.cli-python2-common.txt
%files pyobjc -f build/files.pyobjc.txt
%files ruby -f build/files.ruby.txt
%files perl -f build/files.perl.txt
%files jsc-webkit-common -f build/files.jsc-webkit-common.txt
%files jsc -f build/files.jsc.txt
%files iosurface -f build/files.iosurface.txt
%files cli-devenv-gui-stubs-common -f build/files.cli-devenv-gui-stubs-common.txt
%files gui-stubs -f build/files.gui-stubs.txt

%changelog
* Wed Oct 25 2023 Benjamin Gaillard <git@benjamin.gaillard.name> - 0.1.20231025-1
- Use default build root
- Honor tar compression according to file extension
- Move license file to the core package
- Use appropriate RPM macros
- Make regular copy instead of hard links to avoid filesystem issues
- Use standard POSIX shell and utilities instead of Bash
- Remove Python 2 build dependency

* Tue May 02 2023 Ariel Abreu <facekapow@outlook.com> - 0.1.20230502-1
- Update to latest version and Fedora 37
- Split package into multiple packages (one for each component of Darling)

* Tue Aug 18 2020 Andy Neff <andy@visionsystemsinc.com> - 0.1.20200331-1
- Update for latest version and Fedora 31

* Mon Aug 12 2019 Andy Neff <andy@visionsystemsinc.com> - 0.1-4
- Update for Fedora 30

* Tue Mar 12 2019 Andy Neff <andy@visionsystemsinc.com> - 0.1-3
- Remove bad commented macro, cleanup, and verify master works on Fedora 29

* Wed Jul 18 2018 Andy Neff <andy@visionsystemsinc.com> - 0.1-2
- Update for Fedora 28 and new master

* Tue Jan 23 2018 Andy Neff <andy@visionsystemsinc.com> - 0.1-1
- Initial version working for Fedora 27
