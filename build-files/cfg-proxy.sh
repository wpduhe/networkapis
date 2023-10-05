#!/usr/bin/env bash

log.notice 'Configuring proxy for package manager operations.'

# Proxy configuration
if [[ -n ${PROXYURL} ]]
then
  log.debug "PROXYURL has been set to: '${PROXYURL}'"
  case $OS in
    'debian'|'ubuntu')
      cat << __EOF__ >/etc/apt/apt.conf.d/00-proxy.conf
Acquire {
  HTTP::proxy "${PROXYURL}";
  HTTPS::proxy "${PROXYURL}";
}
__EOF__
      ;;
    'centos'|'fedora'|'almalinux'|'rocky')
      for lFile in /etc/yum.conf /etc/dnf/dnf.conf
      do
        if [ -f $lFile ]
        then
          if grep -q '^proxy=' $lFile
          then
            sed -i.bak "s@proxy=.*@proxy=${PROXYURL}@g" $lFile
          else
            sed -i.bak "/^[main]$/a proxy=\"${PROXYURL}\"" $lFile
          fi
        fi
      done
      ;;
    'alpine')
      :
      ;;
    *)
      log.error 'Failed to configure proxy for package management operations'
      exit 1
      ;;
  esac
else
  log.notice "No proxy configuration specified to be set."
fi

log.notice "Identified proxy configuration on base image."
log.debug "$(env | grep -i proxy | sort)"
cat /etc/apt/apt.conf.d/00*proxy* || true
cat /etc/docker/daemon.json || true
cat ${HOME}/.docker/config.json || true

# Do NOT put an "exit" call as this file is sourced.