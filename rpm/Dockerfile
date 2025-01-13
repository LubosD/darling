ARG OS=fedora:37
FROM ${OS}

SHELL ["/bin/sh", "-euxvc"]

RUN . /etc/os-release; \
    if [ -e /etc/fedora-release ]; then \
      dist=fedora; \
    else \
      dist=el; \
    fi; \
    dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
        dnf-plugins-core git-core rpm-build sudo \
        "https://mirrors.rpmfusion.org/free/${dist}/rpmfusion-free-release-${VERSION_ID%%.*}.noarch.rpm"; \
    dnf clean all

COPY SPECS/darling.spec /darling.spec

# Bootstrap
RUN . /etc/os-release; \
    dnf_options='-y --setopt=install_weak_deps=False --setopt=tsflags=nodocs'; \
    if [ -e /etc/fedora-release ]; then \
      if [ "${VERSION_ID}" -le 38 ]; then \
        dnf install ${dnf_options} python2; \
      fi; \
    else \
      if [ "${VERSION_ID%%.*}" -ge 9 ]; then \
        dnf_options="${dnf_options} --enablerepo=crb --enablerepo=devel"; \
      else \
        dnf install ${dnf_options} python2; \
        dnf_options="${dnf_options} --enablerepo=powertools --enablerepo=devel"; \
      fi; \
    fi; \
    dnf builddep ${dnf_options} /darling.spec; \
    dnf clean all

RUN rm /darling.spec

VOLUME /src /root/rpmbuild

CMD /src/rpm/build.sh
