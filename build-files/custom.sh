#!/usr/bin/bash

# This script must be run by build.sh and not standalone.
if ! (echo $0 | grep build.sh)
then
  echo "This script may not be executed as a standalone."
  exit 1
fi

#                                                                                     #
##                                                                                   ##
### Any application specific customization processes needed should be placed below. ###
##                                                                                   ##
#                                                                                     #
if [[ -s /run/secrets/NEXUSUSER ]]
then
  NEXUSUSER="$(cat /run/secrets/NEXUSUSER)"
  log.notice "NEXUSUSER has been set: $(cat /run/secrets/NEXUSUSER)"
fi
if [[ -s /run/secrets/NEXUSPASS ]]
then
  NEXUSPASS="$(cat /run/secrets/NEXUSPASS)"
  log.notice "NEXUSPASS has been set: $(cat /run/secrets/NEXUSPASS)"
fi

# Copy the "app" directory into the image
pip install --upgrade pip
pip install --extra-index-url https://${NEXUSUSER}:${NEXUSPASS}@nexus.hca.corpad.net/repository/hcanetworkservicespypi/simple --trusted-host nexus.hca.corpad.net -r requirements.txt

# Do NOT put an exit as this file is sourced.
