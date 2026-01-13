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

package wycheproof_test

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

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
	wycheproof.SuiteV1
	TestGroups []*AeadGroup `json:"testGroups"`
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return b
}

func TestPopulateSuiteV1(t *testing.T) {
	suite := new(AeadSuite)
	wycheproof.PopulateSuiteV1(t, suite, "aes_gcm_test.json")
	if suite.Algorithm != "AES-GCM" {
		t.Errorf("suite.Algorithm = %q, want %q", suite.Algorithm, "AES-GCM")
	}
	wantZeroLengthIVNotes := wycheproof.NotesV1{
		BugType:     "AUTH_BYPASS",
		Description: "GCM does not allow an IV of length 0. Encrypting with an IV of length 0 leaks the authentication key. Hence using an IV of length 0 is insecure even if the key itself is only used for a single encryption.",
		CVEs:        []string{"CVE-2017-7822"},
	}
	got := suite.SuiteV1.Notes["ZeroLengthIv"]
	if diff := cmp.Diff(wantZeroLengthIVNotes, got); diff != "" {
		t.Errorf("wycheproof.PopulateSuiteV1 returned unexpected diff (-want +got):\n%s", diff)
	}

	// Test groups.
	if len(suite.TestGroups) == 0 {
		t.Fatalf("len(suite.TestGroups) = %d, want 1", len(suite.TestGroups))
	}
	if len(suite.TestGroups[0].Tests) == 0 {
		t.Fatalf("len(suite.TestGroups[0].Tests) = %d, want 1", len(suite.TestGroups[0].Tests))
	}
	gotTestVector := suite.TestGroups[0].Tests[0]

	wantTestVector := &AeadTest{
		WycheproofCase: testutil.WycheproofCase{
			CaseID:  1,
			Comment: "",
			Result:  "valid",
			Flags:   []string{"Ktv"},
		},
		Key:        mustHexDecode(t, "5b9604fe14eadba931b0ccf34843dab9"),
		IV:         mustHexDecode(t, "028318abc1824029138141a2"),
		Message:    mustHexDecode(t, "001d0c231287c1182784554ca3a21908"),
		AAD:        mustHexDecode(t, ""),
		Ciphertext: mustHexDecode(t, "26073cc1d851beff176384dc9896d5ff"),
		Tag:        mustHexDecode(t, "0a3ea7a5487cb5f7d70fb6c58d038554"),
	}
	if diff := cmp.Diff(wantTestVector, gotTestVector); diff != "" {
		t.Errorf("wycheproof.PopulateSuiteV1 returned unexpected diff (-want +got):\n%s", diff)
	}
}
