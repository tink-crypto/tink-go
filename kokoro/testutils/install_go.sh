#!/bin/bash

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# This script installs a recent version of Go into a temporary directory. The Go
# bin directory is then added to the PATH environment variable.
#
# NOTE: This script MUST be sourced to update the environment of the calling
# script.
#
# Usage instructions:
#
#  source ./kokoro/testutils/install_go.sh

set -eo pipefail

readonly GO_VERSION="1.24.0"
readonly GO_LINUX_AMD64_SHA256="dea9ca38a0b852a74e81c26134671af7c0fbe65d81b0dc1c5bfe22cf7d4c8858"
readonly GO_DARWIN_AMD64_SHA256="7af054e5088b68c24b3d6e135e5ca8d91bbd5a05cb7f7f0187367b3e6e9e05ee"
readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

install_temp_go() {
  local go_platform
  local go_sha256
  case "${PLATFORM}" in
    "linux")
      go_platform="linux-amd64"
      go_sha256="${GO_LINUX_AMD64_SHA256}"
      ;;
    "darwin")
      go_platform="darwin-amd64"
      go_sha256="${GO_DARWIN_AMD64_SHA256}"
      ;;
    *)
      echo "Unsupported platform, unable to install Go."
      exit 1
      ;;
  esac
  readonly go_platform
  readonly go_sha256

  local -r go_archive="go${GO_VERSION}.${go_platform}.tar.gz"
  local -r go_url="https://go.dev/dl/${go_archive}"
  local -r go_tmpdir=$(mktemp -dt tink-go.XXXXXX)
  (
    set -x
    cd "${go_tmpdir}"
    curl -OLsS "${go_url}"
    echo "${go_sha256} ${go_archive}" | sha256sum -c
    tar -xzf "${go_archive}"
  )

  export GOROOT="${go_tmpdir}/go"
  export PATH="${go_tmpdir}/go/bin:${PATH}"
}

if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]] ; then
  install_temp_go
fi
