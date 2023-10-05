#!/usr/bin/env bash

# This script must be run by build.sh and not standalone.
if ! (echo $0 | grep build.sh)
then
  echo "This script may not be executed as a standalone."
  exit 1
fi

# Flag to determine if additional repositories have been added.
typeset -i gUpdatePkgs=0

#                                                                             #
##                                                                           ##
###    Perform repository preparation as necessary below.                   ###
##                                                                           ##
#                                                                             #
case ${OS} in
  'debian'|'ubuntu')
    log.notice 'Installing support packages.'
    # Have to do the following to find the additional packages
    ${PKGMGR} --quiet update
    # Need this to add the add-apt-repository software
    ${PKGMGR} ${PKGMGRCONFIRM} ${PKGMGRARGS} --quiet ${PKGMGRINSTALL} software-properties-common
    # Needed to support pulling GPG keys from sources
    ${PKGMGR} ${PKGMGRCONFIRM} ${PKGMGRARGS} ${PKGMGRINSTALL} curl gettext-base gnupg2 gpg-agent

    # Check for repository keys
    if [ $(grep -Ecv '^#' ./repokeys.txt) -ne 0 ]
    then
      # Add repository keys
      grep -Ev '^#' ./repokeys.txt | envsubst |\
        while read -r lEntry
        do
          lURL=$(echo $lEntry | awk -F',' '{print $1}')
          lKeyFile=$(echo $lEntry | awk -F',' '{print $2}')
          if [[ ${lKeyFile##*.} != gpg ]]; then lKeyFile="${lKeyFile}.gpg"; fi
          log.notice "Pulling key from: '${lURL}'"
          curl -fsSL "${lURL}" | gpg --dearmor >/etc/apt/trusted.gpg.d/${lKeyFile}
          chown root:root /etc/apt/trusted.gpg.d/${lKeyFile}
          chmod ugo+r,go-w /etc/apt/trusted.gpg.d/${lKeyFile}
          #log.debug "$(apt-key list)"
        done
    fi

    # Check for repository list entries
    if [ $(grep -Ecv '^#' ./repolist.txt) -ne 0 ]
    then
      # Add repository sites
      grep -Ev '^#' ./repolist.txt | envsubst |\
        while read -r lEntry
        do
          log.notice "Adding repository: '${lEntry}'"
          ${PKGREPOMGR} ${PKGMGRCONFIRM} "${lEntry}"
        done
      gUpdatePkgs=1
    fi
    ;;
  'centos'|'fedora'|'almalinux'|'rocky')
    :
    ${PKGMGR} ${PKGMGRCONFIRM} ${PKGMGRARGS} ${PKGMGRINSTALL} gettext
    ;;
  '*')
    log.warning "Cannot determine operating system for operation."
    log.notice "Continuing..."
    ;;
esac

if [ $gUpdatePkgs -gt 0 ]
then
  log.notice 'Package list update to address new repository list additions.'
  ${PKGMGR} --quiet update
fi

# Do NOT put an "exit" call as this file is sourced.
