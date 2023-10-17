#!/bin/bash
# Copyright 2023 Google LLC
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

_image_prefix() {
  local -r artifact_registry_url="us-docker.pkg.dev"
  local -r test_project="tink-test-infrastructure"
  local -r artifact_registry_repo="tink-ci-images"
  echo "${artifact_registry_url}/${test_project}/${artifact_registry_repo}"
}

# Linux container images for Tink Go libraries.
readonly TINK_GO_BASE_IMAGE_NAME="linux-tink-go-base"
readonly TINK_GO_BASE_IMAGE_HASH="be963aaf342c6987772dcc3f45018ac38ad1bf324a615cfcd48560f90ad7323f"
readonly TINK_GO_BASE_IMAGE="$(_image_prefix)/${TINK_GO_BASE_IMAGE_NAME}@sha256:${TINK_GO_BASE_IMAGE_HASH}"

unset -f _image_prefix
