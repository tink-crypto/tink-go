// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aescmac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

type testVector struct {
	name          string
	keyBytes      []byte
	message       []byte
	tag           []byte
	variant       aescmac.Variant
	idRequirement uint32
	tagSize       uint32
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex string %q: %v", s, err)
	}
	return b
}

func testVectors(t *testing.T) []testVector {
	testVectors := []testVector{}
	for _, tagSize := range []uint32{10, 16} {
		for _, variant := range []struct {
			value         aescmac.Variant
			prefix        []byte
			idRequirement uint32
		}{
			{aescmac.VariantNoPrefix, nil, 0},
			{aescmac.VariantTink, slices.Concat([]byte{cryptofmt.TinkStartByte}, []byte{0x01, 0x02, 0x03, 0x04}), 0x01020304},
			{aescmac.VariantCrunchy, slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04}), 0x01020304},
		} {
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1851
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("test_vector_1: Variant=%s TagSize=%d", variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97"),
				message:       nil,
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "736c7b56957db774c5ddf7c7a70ba8a8")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1860
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("test_vector_2: Variant=%s TagSize=%d", variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc"),
				message:       mustHexDecode(t, "40"),
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "9d47482c2d9252bace43a75a8335b8b8")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
			// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_cmac_test.json#L1968
			testVectors = append(testVectors, testVector{
				name:          fmt.Sprintf("test_vector_3: Variant=%s TagSize=%d", variant.value, tagSize),
				keyBytes:      mustHexDecode(t, "abab815d51df29f740e4e2079fb798e0152836e6ab57d1536ae8929e52c06eb8"),
				message:       mustHexDecode(t, "f0058d412a104e53d820b95a7f"),
				tag:           slices.Concat(variant.prefix, mustHexDecode(t, "1fa24c6625a0f8e1fc37827ac84d3cc4")[:tagSize]),
				variant:       variant.value,
				idRequirement: variant.idRequirement,
				tagSize:       tagSize,
			})
		}
		// Legacy,
		prefix := slices.Concat([]byte{cryptofmt.LegacyStartByte}, []byte{0x01, 0x02, 0x03, 0x04})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("test_vector_1: Variant=%s TagSize=%d", aescmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97"),
			message:       nil,
			tag:           slices.Concat(prefix, mustHexDecode(t, "f463275d38b29925a8e7c9841d20fc71")[:tagSize]),
			variant:       aescmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("test_vector_1: Variant=%s TagSize=%d", aescmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "e754076ceab3fdaf4f9bcab7d4f0df0cbbafbc87731b8f9b7cd2166472e8eebc"),
			message:       mustHexDecode(t, "40"),
			tag:           slices.Concat(prefix, mustHexDecode(t, "9d651692e63c5ee8197e4bbfeafcf264")[:tagSize]),
			variant:       aescmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
		testVectors = append(testVectors, testVector{
			name:          fmt.Sprintf("test_vector_1: Variant=%s TagSize=%d", aescmac.VariantLegacy, tagSize),
			keyBytes:      mustHexDecode(t, "abab815d51df29f740e4e2079fb798e0152836e6ab57d1536ae8929e52c06eb8"),
			message:       mustHexDecode(t, "f0058d412a104e53d820b95a7f"),
			tag:           slices.Concat(prefix, mustHexDecode(t, "f6b809c40ca31e5dbbb72f364e58cd38")[:tagSize]),
			variant:       aescmac.VariantLegacy,
			idRequirement: 0x01020304,
			tagSize:       tagSize,
		})
	}
	return testVectors
}

func TestMACTestVectors(t *testing.T) {
	for _, tc := range testVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aescmac.NewParameters(aescmac.ParametersOpts{
				KeySizeInBytes: len(tc.keyBytes),
				TagSizeInBytes: int(tc.tagSize),
				Variant:        tc.variant,
			})
			if err != nil {
				t.Fatalf("aescmac.NewParameters(%v, %v) err = %v, want nil", tc.variant, 16, err)
			}
			key, err := aescmac.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), params, tc.idRequirement)
			if err != nil {
				t.Fatalf("aescmac.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, params, tc.idRequirement, err)
			}
			mac, err := aescmac.NewMAC(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("aescmac.NewMAC(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}
			tag, err := mac.ComputeMAC(tc.message)
			if err != nil {
				t.Fatalf("mac.ComputeMAC(%v) err = %v, want nil", tc.message, err)
			}
			if !bytes.Equal(tag, tc.tag) {
				t.Errorf("mac.ComputeMAC(%v) = %x, want %x", tc.message, tag, tc.tag)
			}
			if err := mac.VerifyMAC(tag, tc.message); err != nil {
				t.Errorf("mac.VerifyMAC(%v, %v) err = %v, want nil", tag, tc.message, err)
			}
		})
	}
}

func TestMACFromPublicAPITestVectors(t *testing.T) {
	for _, tc := range testVectors(t) {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aescmac.NewParameters(aescmac.ParametersOpts{
				KeySizeInBytes: len(tc.keyBytes),
				TagSizeInBytes: int(tc.tagSize),
				Variant:        tc.variant,
			})
			if err != nil {
				t.Fatalf("aescmac.NewParameters(%v, %v) err = %v, want nil", tc.variant, 16, err)
			}
			key, err := aescmac.NewKey(secretdata.NewBytesFromData(tc.keyBytes, testonlyinsecuresecretdataaccess.Token()), params, tc.idRequirement)
			if err != nil {
				t.Fatalf("aescmac.NewKey(%v, %v, %v) err = %v, want nil", tc.keyBytes, params, tc.idRequirement, err)
			}
			km := keyset.NewManager()
			id, err := km.AddKey(key)
			if err != nil {
				t.Fatalf("km.AddKey(%v) err = %v, want nil", key, err)
			}
			if err := km.SetPrimary(id); err != nil {
				t.Fatalf("km.SetPrimary(%v) err = %v, want nil", id, err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}
			mac, err := mac.New(handle)
			if err != nil {
				t.Fatalf("mac.New(handle) err = %v, want nil", err)
			}
			tag, err := mac.ComputeMAC(tc.message)
			if err != nil {
				t.Fatalf("mac.ComputeMAC(%v) err = %v, want nil", tc.message, err)
			}
			if !bytes.Equal(tag, tc.tag) {
				t.Errorf("mac.ComputeMAC(%v) = %v, want %v", tc.message, tag, tc.tag)
			}
			if err := mac.VerifyMAC(tag, tc.message); err != nil {
				t.Errorf("mac.VerifyMAC(%v, %v) err = %v, want nil", tag, tc.message, err)
			}
		})
	}
}

func TestDecryptFailsWithInvalidInputs(t *testing.T) {
	for _, variant := range []aescmac.Variant{
		aescmac.VariantNoPrefix,
		aescmac.VariantTink,
		aescmac.VariantCrunchy,
		aescmac.VariantLegacy,
	} {
		t.Run(variant.String(), func(t *testing.T) {
			params, err := aescmac.NewParameters(aescmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				Variant:        variant,
			})
			if err != nil {
				t.Fatalf("aescmac.NewParameters() err = %v, want nil", err)
			}
			keyBytes := secretdata.NewBytesFromData([]byte("01010101010101010101010101010101"), testonlyinsecuresecretdataaccess.Token())
			key, err := aescmac.NewKey(keyBytes, params, 0)
			if err != nil {
				t.Fatalf("aescmac.NewKey() err = %v, want nil", err)
			}
			m, err := aescmac.NewMAC(key, internalapi.Token{})
			if err != nil {
				t.Fatalf("aescmac.NewMAC(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
			}

			message := []byte("Some data to sign.")
			tag, err := m.ComputeMAC(message)
			if err != nil {
				t.Fatalf("m.ComputeMAC(message) err = %v, want nil", err)
			}

			prefix := tag[:len(key.OutputPrefix())]
			rawTag := tag[len(prefix):]

			// Invalid prefix.
			if len(prefix) > 0 {
				wrongPrefix := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				if err := m.VerifyMAC(slices.Concat(wrongPrefix, rawTag), message); err == nil {
					t.Errorf("m.VerifyMAC() err = nil, want error")
				}
			}

			// Corrupted tag.
			wrongTag := bytes.Clone(rawTag)
			wrongTag[0] ^= 1
			if err := m.VerifyMAC(slices.Concat(prefix, wrongTag), message); err == nil {
				t.Errorf("m.VerifyMAC() err = nil, want error")
			}

			// Truncated tag.
			for i := 1; i < len(tag); i++ {
				if err := m.VerifyMAC(tag[:i], message); err == nil {
					t.Errorf("m.VerifyMAC(tag[:%d], message) err = nil, want error", i)
				}
			}

			// Invalid message.
			if err := m.VerifyMAC(tag, []byte("invalid")); err == nil {
				t.Errorf("m.VerifyMAC() err = nil, want error")
			}
		})
	}
}

type AESCMACSuite struct {
	Algorithm     string
	NumberOfTests uint32
	TestGroups    []*testgroup
}

type testgroup struct {
	KeySize uint32
	TagSize uint32
	Type    string
	Tests   []*testcase
}

type testcase struct {
	Comment string
	Key     string
	Msg     string
	Result  string
	Tag     string
	TcID    uint32
}

func TestVectorsWycheproof(t *testing.T) {
	suite := new(AESCMACSuite)
	if err := testutil.PopulateSuite(suite, "aes_cmac_test.json"); err != nil {
		t.Fatalf("testutil.PopulateSuite: %v", err)
	}

	for _, g := range suite.TestGroups {
		for _, tc := range g.Tests {
			if g.KeySize != 256 {
				t.Logf("Key size for test case %d (%s) is not 256, but %d", tc.TcID, tc.Comment, g.KeySize)
				continue
			}
			if g.TagSize%8 != 0 {
				t.Errorf("Requested tag size for test case %d (%s) is not a multiple of 8, but %d", tc.TcID, tc.Comment, g.TagSize)
				continue
			}
			keyBytes := mustHexDecode(t, tc.Key)
			msg := mustHexDecode(t, tc.Msg)
			tag := mustHexDecode(t, tc.Tag)

			t.Run(fmt.Sprintf("test_case_%d", tc.TcID), func(t *testing.T) {
				params := mustCreateParameters(t, aescmac.ParametersOpts{
					KeySizeInBytes: len(keyBytes),
					TagSizeInBytes: int(g.TagSize / 8),
					Variant:        aescmac.VariantNoPrefix,
				})
				key := mustCreateKey(t, secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()), params, 0)
				valid := tc.Result == "valid"
				mac, err := aescmac.NewMAC(key, internalapi.Token{})
				if valid && err != nil {
					t.Fatalf("aescmac.NewMAC(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
				}
				if err == nil {
					res, err := mac.ComputeMAC(msg)
					if valid && err != nil {
						t.Errorf("mac.ComputeMAC(msg) err = %v, want nil", err)
					}
					if valid && !bytes.Equal(res, tag) {
						t.Errorf("mac.ComputeMAC(msg) = %v, want %v", res, tag)
					}
					if !valid && bytes.Equal(res, tag) && err == nil {
						t.Errorf("Compute AES-CMAC and invalid expected (%s) match:\nComputed: %q\nExpected: %q", tc.Comment, res, tag)
					}
					err = mac.VerifyMAC(tag, msg)
					if valid && err != nil {
						t.Errorf("mac.VerifyMAC(tag, msg) err = %v, want nil", err)
					}
					if !valid && err == nil {
						t.Errorf("mac.VerifyMAC(tag, msg) err = nil, want error")
					}
				}
			})
		}
	}
}
