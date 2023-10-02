#!/usr/bin/env bash

# This script must be run by build.sh and not standalone.
if ! (echo $0 | grep build.sh)
then
  echo "This script may not be executed as a standalone."
  exit 1
fi

# Establish HCA's CA configuration
if [ -d files ]
then
  if ls -1 files/*.crt >/dev/null 2>&1
  then
    log.notice "Installing HCA CA certificates."
    if [[ $OS == debian ]] || [[ $OS == ubuntu ]]
    then
      lCADestDir="/usr/local/share/ca-certificates/hca-custom-ca/"
      lCAUpdateCmd="update-ca-certificates"
      if [ ! -d ${lCADestDir} ]
      then
        mkdir --verbose --parents --mode=0755 ${lCADestDir}
      fi
    else
      lCADestDir="/etc/pki/ca-trust/source/anchors/"
      lCAUpdateCmd="update-ca-trust"
    fi
    cp files/*.crt ${lCADestDir}
    chmod 0644 ${lCADestDir}/*
    log.notice "Updating certificate stores."
    ${lCAUpdateCmd}
  fi
fi

# Create "standard" user and group.
log.notice "Creating standard user and group."
if ! grep "${APP_GROUP}:x:${APP_GID}" /etc/group
then
  groupadd -g $APP_GID $APP_GROUP
fi
if ! grep "${APP_USER}:x:${APP_UID}:" /etc/passwd
then
  useradd -u ${APP_UID} -g ${APP_GID} -s /usr/sbin/nologin ${APP_USER}
fi

# Do NOT put an "exit" call as this file is sourced.
