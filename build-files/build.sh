#!/usr/bin/env bash
source ./logger.sh

# Bash "strict mode", to help catch problems and bugs in this shell script.
# (http://redsymbol.net/articles/unofficial-bash-strict-mode/)
set -vx
set -Eeuo pipefail

# Source common settings
if [ -f ./common.sh ]; then source ./common.sh; fi

# Perform proxy preparatory operations (i.e., add keys or repository lists)
log.notice 'Proxy configuration starting.'
if [ -f ./cfg-proxy.sh ]; then source ./cfg-proxy.sh; fi
log.notice 'Proxy configuration complete.'

# Perform any package preparatory operations (i.e., add keys or repository lists)
log.notice 'Repository preparatory operations started.'
if [ -f ./repo-prep.sh ]; then source ./repo-prep.sh; fi
log.notice 'Repository preparatory operations complete.'

if [ ${BASE_PARENT_IMAGE} -eq 0 ]
then
  # Update packages
  log.notice 'Initial package update after preperatory configuration.'
  case $OS in
    'centos'|'fedora'|'almalinux'|'rocky')
      ${PKGMGR} ${PKGMGRCONFIRM} check-update || true
      ${PKGMGR} ${PKGMGRCONFIRM} --exclude="kernel*" update
      ;;
    'debian'|'ubuntu')
      ${PKGMGR} ${PKGMGRCONFIRM} update
      ;;
    *)
      ;;
  esac
  log.notice 'Initial package update complete.'

  # Execute pre-build setup
  log.notice 'Pre-build operations started.'
  if [ -f ./prebuild.sh ]; then source ./prebuild.sh; fi
  log.notice "Pre-build operations complete."
fi

# Install user defined packages
log.notice 'Installing requested packages by name.'
if [ $(grep -Ecv '^#' packages.txt) -ne 0 ]
then
  ${PKGMGR} ${PKGMGRARGS} ${PKGMGRINSTALL} $(grep -Ev '^#' packages.txt | envsubst | awk '{printf(" %s",$1)};END{printf("\n");}')
fi
log.notice "Named package installation complete."

# Install any updates from rpm packages located
# WORKDIR is set to /opt/app in the parent Dockerfile
if [ -d pkgs ]
then
  cd pkgs
  log.notice 'Installing requested packages by file.'
  if ls *.${PKGEXT} >/dev/null 2>&1
  then
    ${PKGMGR} ${PKGMGRARGS} ${PKGMGRCONFIRM} ${PKGMGRINSTALL} $(ls -1 *.${PKGEXT} | awk '{printf(" ./%s",$1)}')
  fi
  cd -
  log.notice 'Package file installation complete.'
fi

# Perform any configuration customizations
log.notice 'Performing specific application customizations.'
if [ -f ./custom.sh ]; then source ./custom.sh; fi
log.notice 'Specific application customizations complete.'

# Delete cached files we don't need anymore:
log.notice 'Cleaning up starting.'
${PKGMGR} ${PKGMGRCONFIRM} ${PKGMGRCLEANARGS}

# Delete all temporary files
if [[ $OS == debian ]] || [[ $OS == ubuntu ]]
then
  rm -fr /var/lib/apt/lists/*
else
  rm -fr /var/cache/dnf/*
  rm -fr /tmp/*
fi
log.notice 'Cleaning up complete.'

exit 0
