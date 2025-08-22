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

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: 2e4a047132d27d9948be (to quickly find the script from logs)"
echo "==========================================================================="

set -euo pipefail

TINK_GO_PROJECT_PATH="$(pwd)"
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  TINK_GO_PROJECT_PATH="${TINK_BASE_DIR}/tink_go"
  cd "${TINK_GO_PROJECT_PATH}"
fi
readonly TINK_GO_PROJECT_PATH

# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

(
  set -x
  go build -v ./...
  go test -v ./...
)
