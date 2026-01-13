// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package wycheproof contains types for parsing Wycheproof test vectors.
package wycheproof

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	// BaseDir is populated in init() depending on whether the test is running
	// with Bazel or not.
	BaseDir string
)

// Wycheproof version to fetch.
const wycheproofModVer = "v0.0.0-20250901140545-b51abcfb8daf"

// downloadTestVectors downloads the JSON test files from
// the Wycheproof repository with `go mod download -json` and returns the
// absolute path to the root of the downloaded source tree.
func downloadTestVectors() (string, error) {
	path := "github.com/C2SP/wycheproof@" + wycheproofModVer
	cmd := exec.Command("go", "mod", "download", "-json", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run `go mod download -json %s`, output: %s", path, output)
	}
	var dm struct {
		Dir string // absolute path to cached source root directory
	}
	if err := json.Unmarshal(output, &dm); err != nil {
		return "", err
	}
	return dm.Dir, nil
}

const testdataDir = "testdata"

func init() {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if ok {
		// If running with `bazel test` TEST_WORKSPACE is set.
		// We don't panic if TEST_WORKSPACE is not set to allow running benchmarks
		// internally at Google, which set TEST_SRCDIR but not TEST_WORKSPACE.
		BaseDir = filepath.Join(srcDir, os.Getenv("TEST_WORKSPACE"), testdataDir)
	} else {
		// Running tests with `go test`.
		var err error
		if BaseDir, err = downloadTestVectors(); err != nil {
			panic(err)
		}
	}
}
