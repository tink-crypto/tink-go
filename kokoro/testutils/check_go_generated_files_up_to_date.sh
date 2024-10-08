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

# This scripts checks that a given Go workspace has its generated Bazel files up
# to date.

usage() {
  echo "Usage: $0 [-h] [-c <compat value (default 1.19)>] <go project dir>"
  echo "  -c: Value to pass to `-compat`. Default to 1.19."
  echo "  -h: Help. Print this usage information."
  exit 1
}

COMPAT="1.19"
GO_PROJECT_DIR=

process_args() {
  # Parse options.
  while getopts "hc:" opt; do
    case "${opt}" in
      c) COMPAT="${OPTARG}" ;;
      *) usage ;;
    esac
  done
  shift $((OPTIND - 1))
  readonly GO_PROJECT_DIR="$1"
  if [[ -z "${GO_PROJECT_DIR}" ]]; then
    usage
  fi
}

main() {
  process_args "$@"

  (
    cd "${GO_PROJECT_DIR}"
    local -r temp_dir_current_generated_files="$(mktemp -dt \
      current_tink_go_build_files.XXXXXX)"
    local -r go_generated_files=(
      ./go.mod
      ./go.sum
    )

    # Copy all current generated files into temp_dir_current_generated_files.
    local -r current_go_generated_files=( "${go_generated_files[@]}" )
    for generated_file_path in "${current_go_generated_files[@]}"; do
      mkdir -p \
        "$(dirname \
          "${temp_dir_current_generated_files}/${generated_file_path}")"
      cp "${generated_file_path}" \
        "${temp_dir_current_generated_files}/${generated_file_path}"
    done

    # Update build files.
    go mod tidy -compat="${COMPAT}"

    # Compare current with new build files.
    local -r new_go_generated_files=( "${go_generated_files[@]}" )

    for generated_file_path in "${new_go_generated_files[@]}"; do
      if ! cmp -s "${generated_file_path}" \
          "${temp_dir_current_generated_files}/${generated_file_path}"; then
        echo "ERROR: ${generated_file_path} needs to be updated. Please follow \
the instructions on go/tink-workflows#update-go-build." >&2
        echo "Diff for ${generated_file_path}:"
        diff "${generated_file_path}" \
          "${temp_dir_current_generated_files}/${generated_file_path}"
        exit 1
      fi
    done
  )
}

main "$@"
