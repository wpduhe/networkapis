# syntax=docker/dockerfile:1
#
# Dockerfile
# Documentation: https://docs.docker.com/engine/reference/builder/
#
# This Dockerfile's purpose is to establish a basis for building a parent image
# for future use in building application images.  It is not specifically a
# base image by definition (i.e., base images have 'scratch' as their source).
#
# The base/parent images used to source a parent image for HCA should be pulled
# utilizing HCA's Nexus Repository Manager which supports proxying of remote
# docker registries.
# The Nexus equivalent URL to those registries follow:
#
# hca-enterprise-docker-proxy.repos.medcity.net
#
# The above proxy mirrors many docker registries including, but not limited to:
# docker.io, quay.io, registry.access.redhat.com, registry.connect.redhat.com,
# and registry.redhat.io.
#
FROM REQD_SOURCE_IMAGE_URL

# The following ARG is to allow granular control of the image build.  If the image
# being built is not a base or parent and is using a managed HCA base/parent image
# then the necessity to update the base operating system packages in not required.
# Setting the BASE_PARENT_IMAGE argument (flag) to a value of zero will prevent
# update of the operating system packages.
ARG BASE_PARENT_IMAGE=1
# The PROXYURL argument is set to an empty/null content on purpose to allow the build
# scripts to behave in a particular manner.  It should not be modified here unless the
# desired result is to have a proxy configuration made static.
ARG PROXYURL=
# The IMAGE_VERSION argument is used by the build workflows - DO NOT ALTER
ARG IMAGE_VERSION
# The following may be overridden by utilizing the --build-arg option.
ARG APP_USER=appuser
ARG APP_UID=1001
ARG APP_GROUP=appgroup
ARG APP_GID=9001
ARG COMPANY_NAME="HCA Healthcare"
ARG ORGANIZATION_NAME="Public Cloud & SRE"
ARG DEPARTMENT_NAME="Container Platform Administration"

LABEL company="${COMPANY_NAME}"
LABEL organization="${ORGANIZATION_NAME}"
LABEL department="${DEPARTMENT_NAME}"
# DO NOT remove or modify the following label as it is used by the included
# GitHub Actions workflow.
LABEL version=$IMAGE_VERSION

ENV http_proxy=${PROXYURL}
ENV https_proxy=${PROXYURL}

# This is a base image which must run as root during build processing
USER root

# Setting a general location for application content
WORKDIR /build

# This "template" is set up to use an installation script to assist in minimizing
# the layers of the resulting container image.
COPY --chmod=0755 ./build-files/* ./
RUN chmod 0644 ./*.txt && ./build.sh && rm -rf /build

WORKDIR /opt/app

CMD ["/bin/bash"]
