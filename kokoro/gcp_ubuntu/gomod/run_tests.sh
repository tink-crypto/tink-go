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

# By default when run locally this script runs the command below directly on the
# host. The CONTAINER_IMAGE variable can be set to run on a custom container
# image for local testing. E.g.:
#
# CONTAINER_IMAGE="s-docker.pkg.dev/tink-test-infrastructure/linux-tink-go-base:latest" \
#  sh ./kokoro/gcp_ubuntu/gomod/run_tests.sh

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: c0e803678984485c75eb (to quickly find the script from logs)"
echo "==========================================================================="

set -euo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_go"
  source "./kokoro/testutils/go_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_GO_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/check_go_generated_files_up_to_date.sh .

cat <<EOF > env_variables.txt
GOARCH
EOF

RUN_COMMAND_ARGS+=( -e env_variables.txt )

readonly RUN_COMMAND_ARGS

cat <<EOF > _run_test.sh
#!/bin/bash
set -euo pipefail

set -x
go build -v ./...
go test -v ./...
EOF

chmod +x _run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _run_test.sh
  rm -rf env_variables.txt
}

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" \
  ./_run_test.sh
