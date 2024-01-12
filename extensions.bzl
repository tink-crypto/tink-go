# Copyright 2024 Google LLC
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

"""Tink Go Bzlmod extensions."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _wycheproof_impl(_ctx):
    # Commit from 2023-11-03.
    http_archive(
        name = "wycheproof",
        strip_prefix = "wycheproof-d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d",
        url = "https://github.com/google/wycheproof/archive/d9f6ec7d8bd8c96da05368999094e4a75ba5cb3d.zip",
        sha256 = "d2a5dd0226183ec01514ebb46abbd77ed349f1c39f570d5f3b0617d652d9a3f4",
    )

wycheproof_extension = module_extension(
    implementation = _wycheproof_impl,
)
