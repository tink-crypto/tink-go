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

package aescmac_test

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/internal/testing/wycheproof"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

func TestNewWrongKeySize(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{
			name: "too short",
			key:  []byte{0x01, 0x02},
		},
		{
			name: "too long",
			key: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aescmac.New(tc.key); err == nil {
				t.Errorf("aescmac.New(%x) err = nil, want error", tc.key)
			}
		})
	}
}

func xorEnd(data, last []byte) []byte {
	dataXOREnd := slices.Clone(data)
	subtle.XORBytes(dataXOREnd[len(data)-aescmac.BlockSize:], data[len(data)-aescmac.BlockSize:], last)
	return dataXOREnd
}

func TestXOREndAndCompute(t *testing.T) {
	key := random.GetRandomBytes(32)
	a, err := aescmac.New(key)
	if err != nil {
		t.Fatalf("aescmac.New(%x) err = %v, want nil", key, err)
	}
	for _, size := range []uint32{16, 19, 33, 64, 110} {
		data := random.GetRandomBytes(size)
		lastBlock := random.GetRandomBytes(aescmac.BlockSize)
		want := a.Compute(xorEnd(data, lastBlock))
		got, err := a.XOREndAndCompute(data, lastBlock)
		if err != nil {
			t.Fatalf("a.XOREndAndCompute(%x, %x) err = %v, want nil", data, lastBlock, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("a.XOREndAndCompute(%x, %x) = %x, want %x", data, lastBlock, got, want)
		}
	}
}

func TestXOREndAndComputeFailsWithInvalidInputs(t *testing.T) {
	key := random.GetRandomBytes(32)
	a, err := aescmac.New(key)
	if err != nil {
		t.Fatalf("aescmac.New(%x) err = %v, want nil", key, err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		last  []byte
		block []byte
	}{
		{
			name: "last is too short",
			data: random.GetRandomBytes(16),
			last: random.GetRandomBytes(15),
		},
		{
			name: "data is too short",
			data: random.GetRandomBytes(15),
			last: random.GetRandomBytes(16),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.XOREndAndCompute(tc.data, tc.last); err == nil {
				t.Errorf("a.XOREndAndCompute(%x, %x) err = nil, want error", tc.data, tc.last)
			}
		})
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) err = %v, want nil", s, err)
	}
	return b
}

func TestVectorsRFC4493(t *testing.T) {
	// Test vectors from RFC 4493.
	key := mustHexDecode(t, "2b7e151628aed2a6abf7158809cf4f3c")
	data := mustHexDecode(t,
		"6bc1bee22e409f96e93d7e117393172a"+
			"ae2d8a571e03ac9c9eb76fac45af8e51"+
			"30c81c46a35ce411e5fbc1191a0a52ef"+
			"f69f2445df4f9b17ad2b417be66c3710")
	expected := map[int][]byte{
		0:  mustHexDecode(t, "bb1d6929e95937287fa37d129b756746"),
		16: mustHexDecode(t, "070a16b46b4d4144f79bdd9dd04a287c"),
		40: mustHexDecode(t, "dfa66747de9ae63030ca32611497c827"),
		64: mustHexDecode(t, "51f0bebf7e3b9d92fc49741779363cfe"),
	}
	a, err := aescmac.New(key)
	if err != nil {
		t.Fatalf("aescmac.New(%x) err = %v, want nil", key, err)
	}
	for inputSize, want := range expected {
		if output := a.Compute(data[:inputSize]); !bytes.Equal(output, want) {
			t.Errorf("a.Compute(data[:inputSize]) = %x, want %x", output, want)
		}
	}
}

type macSuite struct {
	wycheproof.SuiteV1
	TestGroups []*macGroup `json:"testGroups"`
}

type macGroup struct {
	testutil.WycheproofGroup
	KeySize uint32     `json:"keySize"`
	TagSize uint32     `json:"tagSize"`
	Type    string     `json:"type"`
	Tests   []*macCase `json:"tests"`
}

type macCase struct {
	testutil.WycheproofCase
	Key     testutil.HexBytes `json:"key"`
	Message testutil.HexBytes `json:"msg"`
	Tag     testutil.HexBytes `json:"tag"`
}

func TestAESCMACPRFWycheproofCases(t *testing.T) {
	suite := new(macSuite)
	wycheproof.PopulateSuiteV1(t, suite, "aes_cmac_test.json")
	for _, group := range suite.TestGroups {
		groupName := fmt.Sprintf("%s-%s-%d", suite.Algorithm, group.Type, group.KeySize)
		if group.TagSize%8 != 0 {
			t.Errorf("For %s, requested tag size is not a multiple of 8, but %d", groupName, group.TagSize)
			continue
		}
		for _, test := range group.Tests {
			caseName := fmt.Sprintf("%s:Case-%d", groupName, test.CaseID)
			t.Run(caseName, func(t *testing.T) {
				if uint32(len(test.Key))*8 != group.KeySize {
					t.Fatalf("Invalid key length: %s", test.Comment)
				}
				cmac, err := aescmac.New(test.Key)
				switch test.Result {
				case "valid":
					if err != nil {
						t.Fatalf("aescmac.New(%x) err = %v, want nil", test.Key, err)
					}
					if res := cmac.Compute(test.Message); !bytes.Equal(res, test.Tag) {
						t.Errorf("cmac.Compute() = %x, want %x", res, test.Tag)
					}
				case "invalid":
					if err != nil {
						return
					}
					if res := cmac.Compute(test.Message); bytes.Equal(res, test.Tag) {
						t.Errorf("cmac.Compute() err = %v and expected result match", err)
					}
				default:
					t.Fatalf("Unsupported test result: %q", test.Result)
				}
			})
		}
	}
}
