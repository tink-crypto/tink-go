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
# CONTAINER_IMAGE="gcr.io/tink-test-infrastructure/linux-tink-go-base:latest" \
#  sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
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

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/check_go_generated_files_up_to_date.sh .

RUN_BAZEL_TESTS_OPTS=(
  -t
  --test_arg=--test.v
)
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  RUN_BAZEL_TESTS_OPTS+=(
    -c "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_GO_BASE_IMAGE_HASH}"
  )
fi
readonly RUN_BAZEL_TESTS_OPTS

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/run_bazel_tests.sh "${RUN_BAZEL_TESTS_OPTS[@]}" .
