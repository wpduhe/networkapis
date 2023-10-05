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

# Install packages
# pip install -r requirements.txt

# Do NOT put an exit as this file is sourced.