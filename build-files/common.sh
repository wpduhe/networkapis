#!/usr/bin/env bash

# This script is sourced to established common environment variables.

# This script must be run by build.sh and not standalone.
if ! (echo $0 | grep build.sh)
then
  echo "This script may not be executed as a standalone."
  exit 1
fi

# Determine base os
if [ -f /etc/os-release ]
then
  set -o allexport; source /etc/os-release; set +o allexport
  echo; env | sort; echo
  export OS=$ID
  case ${OS} in
    'centos'|'fedora'|'almalinux'|'rocky')
       if [ -x /usr/bin/microdnf ]
       then
         export PKGMGR="microdnf"
       else
         export PKGMGR="dnf"
       fi
       export PKGMGRINSTALL="install"
       export PKGMGRCONFIRM="--yes"
       export PKGMGRCLEANARGS="clean all"
       export PKGMGRARGS="--nodocs --best --setopt=tsflags=nodocs --setopt=install_weak_deps=False --quiet"
       export PKGEXT="rpm"
       export PKGREPOMGR="${PKGMGR} config-manager --add-repo"
       ;;
    'debian'|'ubuntu')
       export PKGMGR="apt-get"
       export PKGMGRINSTALL="install"
       export PKGMGRCONFIRM="--yes"
       export PKGMGRCLEANARGS="clean all"
       export PKGMGRARGS="--no-install-recommends --quiet"
       export PKGEXT="deb"
       export PKGREPOMGR="add-apt-repository"
       export PKGKEYMGR="apt-key"
       # Tell apt-get we're never going to be able to give manual feedback
       export DEBIAN_FRONTEND=noninteractive
       export ARCH="$(dpkg --print-architecture)"; \
       ;;
    'alpine')
       export PKGMGR="apk"
       export PKGMGRINSTALL="add"
       export PKGMGRCONFIRM=""
       export PKGMGRCLEANARGS="cache clean --purge"
       export PKGMGRARGS=""
       export PKGEXT="deb"
       export PKGREPOMGR="add-apt-repository"
       export PKGKEYMGR="apt-key"
       ;;
    '*')
      log.error "ERROR: Base operating system is not compatible with this build method."
      exit 1
      ;;
  esac
else
  log.error "Cannot determine the base operating system."
  exit 1
fi

# Do NOT put an "exit" call as this file is sourced.
