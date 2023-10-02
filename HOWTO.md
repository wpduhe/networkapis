# Near Future Implementation
This template is being incorporated into the Internal Developer Platform (IDP) effort lead by Jason Bandy's organization.  When that work is completed the developer will create the repository through the Backstage.io User Interface (UI) by completing formatted inputs.

<br/>

# How to use this template

## Overview

This template is just that - a template. Its purpose is to be a starting point in developing a parent container image. It contains files basic to getting started in building a containerized parent image including Dockerfile and GitHub Action workflows for building.

<br/>

## Getting Started
To be completely transparent, the container image described has been frequently (and, yes, even by the author) referred to as a *base* image. That is not completely accurate. A *base* image's source is a special *scratch* image which this process is not invoking. Instead it is designed to create a *parent* image which is sourced from an existing *base* image (i.e., ubnuntu, almalinux, rockylinux, centos-stream, etc.).

The Dockerfile provided in this template contains argument (ARG) specifications that may and in some cases must be modified to complete the build of a parent image. The arguments will be referenced throughout the remainder of this document.

<br/>

### Base Image Selection
The source image used in the creation of the new parent image should be pulled through HCA's central repository management system, [Nexus](https://nexus.hca.corpad.net). This is achieved by utilizing ```hca-enterprise-docker-proxy.repos.medcity.net``` as a prefix and setting the subsequent suffix text to the desired image name. Using this location helps to ensure that the image present has been scanned by HCA security tools. It is the responsibility of the application development team using this method to ensure that updates to the selected base image are maintained. The following is an example of pulling the Ubuntu container base image through the Nexus system which proxies the connection to Docker HUB.

```Dockerfile
FROM hca-enterprise-docker-proxy.repos.medcity.net/ubuntu:22.04
```

Developers are strongly encouraged, recommended, to utilize the parent images provided by the Public Cloud & SRE, Container Platform Administration (CPA) team's managed images. These are available through the Nexus repository manager under the ```containers/base``` folder.

A list of the available images from the CPA team may be found in the Confluence [Maintained Base Images](https://confluence.app.medcity.net/c/display/GKEG/Maintained+Base+Images) page.

```Dockerfile
FROM hca-docker-innersource.repos.medcity.net/containers/base/centos-stream8:latest
```

<br/>

### Labels
Labels are utlized to help identify the respective onwership of the created image. This helps to direct questions related to the image to the appropriate organization and department. These labels are populated by utilizing the following Dockerfile arguments.

|Label|Default|Notes|
|-----|-------|-----|
|COMPANY_NAME|"HCA Healthcare"||
|ORGANIZATION_NAME|"Public Cloud & SRE"||
|DEPARTMENT_NAME|"Container Platform Administration"||
|IMAGE_VERSION||Automatically populated by reusable workflow.|
|

<br/>

### Build Scripts, Directories, & Files
There are build scripts, directories and files to designed to minimize the developer's input in the building an image. The following table describes each of these items.

|Item|Purpose|Notes|
|------|-------|-----|
|build.sh|Primary driver sourcing all other scripts which are not callable outside this script.|No modification should be made to this file.|
|common.sh|Abstracts operating system specific calls as common variable declarations.|No modification should be made to this file.
|prebuild.sh|Performs specific actions to install the HCA certificate authority keys and the creation of the container's operational user and group.|The script may be modified to include additional actions to support the desired build content. The user and group default values may be overridden using Dockerfile arguments: APP_USER, APP_UID, APP_GROUP, APP_GID.|
|cfg-proxy.sh|Sets the proxy configuration for the operating system's package management's utilization.|No modification should be made to this file. It utilizes the PROXYURL Dockerfile argument to set the proxy URL value to be configured.|
|repo-prep.sh|Establishes repository keys and package site definitions appropriately for the respective operating system's package management.|This script utilizes the ```repokeys.txt``` and ```repolist.txt``` files to define the content in creating the package management configuration.
|logger.sh|Provides the ```log``` function to provide session feedback in a consistent fashion.|No modification should be made to this file.|
|custom.sh|Provides a place for any modifciations required for the build not already addressed by the other build scripts, directories, and files.|This file is expected to have modifications made to it.|
|repokeys.txt|Contains a list of URLs (one per line) which resolve to signature keys for package management sites added via the ```repolist.txt``` file.||
|repolist.txt|Contains a list of strings (one per line) which map to package management sites.||
|packages.txt|Contains a list of strings (one per line) which represent packages to be installed by the package management system.||
|pkgs|Directory which is expected to contain packages (i.e., RPM, DPKG) to be installed.|This is typically utilized when the package to be installed cannot be *named* as in the ```packages.txt``` file or is not available for the configured package management operating system. For example, a vulnerability fix which is available, but not in the configured package management operating system version.|
|files|Contains files to be utilized by the build scripts.|This directory contains the HCA CA files used in the ```prebuild.sh``` script. Any additional support files may be added to this directory which will be available to the build scripts during build processing.|

<br/>

### Workflows

Workflows are located within the ```.github/workflows``` sub-directory within the repository.

There are three workflows present in this repository template to support the development of containerized application images: **build**, **nightly**, and **changelog**.

Each workflow must be reviewed to address the placeholder strings (i.e., REQD_*). These must be replaced to reflected the application to be built.

**NOTE:** The following workflows utilize the CPA ru-container-image-build workflow. This workflow requires that a *secret* is provided for the Wiz.io scanning. (The application team will need to request this from the CPA team.)

<br/>

#### Build

This workflow is intended to be used to create the *production* ready image.

<br/>

#### Nightly

This workflow is intended to be used to create a daily build of the application image from the very latest sources and should not be used for production deployments. It will be tagged with **nightly** and identified as a _pre-release_ within this repository.

<br/>

#### Changelog

This workflow will automatically build the `CHANGELOG.md` file from extracted commit commentary when a pull_request is closed, a release is published, or when issues are edited or closed.

<br/>

## Putting It All Together
The reusable workflow (```HCACPA/.github/.github/workflows/ru-container-image-build```) which is employed by the contained build and nightly workflows, initiates a docker build utilizing the presented Dockerfile.  The reusable workflow provides for consistent build processing addressing the following items:
* Linting validation of the presented Dockerfile,
* Increments or establishes a version tag and release,
* Builds the image,
* Tests the image (rudimentary test to ensure it runs),
* Scanning for security vulnerabilities,
* Pushes the resulting image to a specified repository
* Pushes the resulting image to the HCA Innersource repository (if desired).

The following is an example call of the ```ru-container-image-build``` reusable workflow found in the build workflow (i.e., .github/workflow/build.yaml). The available inputs to the workflow are documented in the [ru-container-image-build](https://github.com/HCACPA/.github/blob/main/docs/ru-container-image-build.md) source repository.

```yaml
name: CentOS-Stream8 Image Build

on:
  schedule:
    - cron: '0 0 1 2,5,8,11 *'
  push:
    branches:
      - main
  pull_request:
    types:
      - closed
  workflow_dispatch:

jobs:
  build-image:
    uses: HCACPA/.github/.github/workflows/ru-container-image-build.yml@v0.0.7
    secrets:
      registry-username: ${{ secrets.CPA_REGISTRY_USERNAME }}
      registry-password: ${{ secrets.CPA_REGISTRY_PASSWORD }}
      wiz-client-id: ${{ secrets.WIZ_CLIENT_ID }}
      wiz-client-secret: ${{ secrets.WIZ_CLIENT_SECRET }}
    with:
      action-runner-list: '["arc","azure","hcacpa","self-hosted"]'
      image-name: 'containers/base/centos-stream8'
      innersource-push: true
      registry: 'cpa.repos.medcity.net'
```

The typical items to be modified by the developer are the ```secrets```, ```image-name```, and ```registry```.

**NOTE:** *The **WIZ_CLIENT_ID** and **WIZ_CLIENT_SECRET** will be provided by the Public Cloud & SRE, Container Platform Administration team upon request. The team has established this with the Wiz Administration Team for use by all development teams.

<br/>
