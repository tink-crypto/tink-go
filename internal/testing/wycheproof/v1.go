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

package wycheproof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// NotesV1 represents the notes field of the top level
// object in a Wycheproof JSON file.
type NotesV1 struct {
	BugType     string   `json:"bugType"`
	Description string   `json:"description"`
	Effect      string   `json:"effect"`
	CVEs        []string `json:"cves"`
	Links       []string `json:"links"`
}

// SuiteV1 represents the common elements of the top level
// object in a Wycheproof JSON file. Implementations should embed
// SuiteV1 in a struct that strongly types the testGroups
// field. See wycheproofutil_test.go for an example.
type SuiteV1 struct {
	Algorithm     string             `json:"algorithm"`
	NumberOfTests int                `json:"numberOfTests"`
	Notes         map[string]NotesV1 `json:"notes"`
}

// PopulateSuiteV1 opens filename from the Wycheproof testvectors_v1 test
// vectors directory and populates suite with the decoded JSON data.
func PopulateSuiteV1(t *testing.T, suite any, filename string) {
	t.Helper()
	f, err := os.Open(filepath.Join(BaseDir, "testvectors_v1", filename))
	if err != nil {
		t.Fatalf("failed to open file %s: %s", filename, err)
	}
	parser := json.NewDecoder(f)
	if err := parser.Decode(suite); err != nil {
		t.Fatalf("failed to decode file %s: %s", filename, err)
	}
}
