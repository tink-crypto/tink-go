// Copyright 2019 Google LLC
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

package testutil_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tink-crypto/tink-go/v2/testutil"
)

func TestPopulateSuite(t *testing.T) {
	type AeadTest struct {
		testutil.WycheproofCase
		Key        testutil.HexBytes `json:"key"`
		IV         testutil.HexBytes `json:"iv"`
		AAD        testutil.HexBytes `json:"aad"`
		Message    testutil.HexBytes `json:"msg"`
		Ciphertext testutil.HexBytes `json:"ct"`
		Tag        testutil.HexBytes `json:"tag"`
	}

	type AeadGroup struct {
		testutil.WycheproofGroup
		Tests []*AeadTest `json:"tests"`
	}

	type AeadSuite struct {
		testutil.WycheproofSuite
		TestGroups []*AeadGroup `json:"testGroups"`
	}

	suite := new(AeadSuite)
	if err := testutil.PopulateSuite(suite, "aes_gcm_test.json"); err != nil {
		t.Fatalf("error populating suite: %s", err)
	}

	if suite.Algorithm != "AES-GCM" {
		t.Errorf("suite.Algorithm=%s, want AES-GCM", suite.Algorithm)
	}

	if suite.TestGroups[0].Tests[0].Key == nil {
		t.Error("suite.TestGroups[0].Tests[0].Key is nil")
	}
}

func TestPopulateSuite_FileOpenError(t *testing.T) {
	suite := new(testutil.WycheproofSuite)
	err := testutil.PopulateSuite(suite, "NON_EXISTENT_FILE")
	if err == nil {
		t.Error("succeeded with non-existent file")
	}
	if _, ok := err.(*os.PathError); !ok {
		t.Errorf("unexpected error for non-existent file: %s", err)
	}
}

func TestPopulateSuite_DecodeError(t *testing.T) {
	var suite *testutil.WycheproofSuite
	err := testutil.PopulateSuite(suite, "aes_gcm_test.json")
	if err == nil {
		t.Error("succeeded with nil suite")
	}
	if _, ok := err.(*json.InvalidUnmarshalError); !ok {
		t.Errorf("unexpected error for decode error: %s", err)
	}
}

func TestHexBytes(t *testing.T) {
	validHex := []byte("abc123")
	want, err := hex.DecodeString(string(validHex))
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", validHex, err)
	}

	var got testutil.HexBytes
	if err = got.UnmarshalText(validHex); err != nil {
		t.Fatalf("hb.UnmarshalText(%q) err = %v, want nil", validHex, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("hb.UnmarshalText(%q); hb = %v, want %v", validHex, got, want)
	}
}

func TestHexBytes_DecodeError(t *testing.T) {
	invalidHex := []byte("xyz")
	var hb testutil.HexBytes
	err := hb.UnmarshalText(invalidHex)
	if err == nil {
		t.Errorf("hb.UnmarshalText(%q) = nil, want err", invalidHex)
	}
}
