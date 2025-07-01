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

package aesctrhmac_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
)

func TestNewParameters_InvalidKeySize(t *testing.T) {
	for _, derivedKeySize := range []int{16, 32} {
		t.Run(fmt.Sprintf("derivedKeySize=%d, keySize=%d", derivedKeySize, derivedKeySize-1), func(t *testing.T) {
			_, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
				KeySizeInBytes:        derivedKeySize - 1,
				DerivedKeySizeInBytes: derivedKeySize,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    16,
				SegmentSizeInBytes:    256,
			})
			if err == nil {
				t.Errorf("NewParameters() err = nil, want error")
			}
		})
	}
}

func TestNewParameters_InvalidDerivedKeySize(t *testing.T) {
	for _, derivedKeySize := range []int{0, 15, 33} {
		t.Run(fmt.Sprintf("derivedKeySize=%d", derivedKeySize), func(t *testing.T) {
			_, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
				KeySizeInBytes:        derivedKeySize,
				DerivedKeySizeInBytes: derivedKeySize,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    16,
				SegmentSizeInBytes:    256,
			})
			if err == nil {
				t.Errorf("NewParameters() err = nil, want error")
			}
		})
	}
}

func TestNewParameters_InvalidHkdfHashType(t *testing.T) {
	_, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HkdfHashType:          aesctrhmac.UnknownHashType,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    16,
		SegmentSizeInBytes:    256,
	})
	if err == nil {
		t.Errorf("NewParameters() err = nil, want error")
	}
}

func TestNewParameters_InvalidHmacHashType(t *testing.T) {
	_, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.UnknownHashType,
		HmacTagSizeInBytes:    16,
		SegmentSizeInBytes:    256,
	})
	if err == nil {
		t.Errorf("NewParameters() err = nil, want error")
	}
}

func TestNewParameters_InvalidTagSize(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts aesctrhmac.ParametersOpts
	}{
		{
			name: "SHA1_tag_size_9",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA1,
				HmacTagSizeInBytes:    9,
				SegmentSizeInBytes:    256,
			},
		},
		{
			name: "SHA1_tag_size_21",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA1,
				HmacTagSizeInBytes:    21,
				SegmentSizeInBytes:    256,
			},
		},
		{
			name: "SHA256_tag_size_9",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    9,
				SegmentSizeInBytes:    256,
			},
		},
		{
			name: "SHA256_tag_size_33",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA256,
				HmacTagSizeInBytes:    33,
				SegmentSizeInBytes:    256,
			},
		},
		{
			name: "SHA512_tag_size_9",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA512,
				HmacTagSizeInBytes:    9,
				SegmentSizeInBytes:    256,
			},
		},
		{
			name: "SHA512_tag_size_65",
			opts: aesctrhmac.ParametersOpts{
				KeySizeInBytes:        16,
				DerivedKeySizeInBytes: 16,
				HkdfHashType:          aesctrhmac.SHA256,
				HmacHashType:          aesctrhmac.SHA512,
				HmacTagSizeInBytes:    65,
				SegmentSizeInBytes:    256,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := aesctrhmac.NewParameters(tc.opts); err == nil {
				t.Errorf("NewParameters() err = nil, want error")
			}
		})
	}
}

func TestNewParameters_InvalidCiphertextSegmentSize(t *testing.T) {
	_, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HkdfHashType:          aesctrhmac.SHA256,
		HmacHashType:          aesctrhmac.SHA256,
		HmacTagSizeInBytes:    16,
		SegmentSizeInBytes:    40, // derivedKeySize(16) + tagSize(16) + noncePrefix(7) + headerLength(1) = 40. Should be at least 41.
	})
	if err == nil {
		t.Errorf("NewParameters() err = nil, want error")
	}
}

type parametersTestCases struct {
	name          string
	parameterOpts aesctrhmac.ParametersOpts
}

func getParametersTestCases(t *testing.T) []parametersTestCases {
	t.Helper()
	var testCases []parametersTestCases
	for _, derivedKeySize := range []int{16, 32} {
		for _, hkdfHashType := range []aesctrhmac.HashType{aesctrhmac.SHA1, aesctrhmac.SHA256, aesctrhmac.SHA512} {
			for _, ht := range []struct {
				hashType aesctrhmac.HashType
				hashSize int
			}{{aesctrhmac.SHA1, 20}, {aesctrhmac.SHA256, 32}, {aesctrhmac.SHA512, 64}} {
				hmacHashType := ht.hashType
				hmacTagSize := ht.hashSize
				testCases = append(testCases, parametersTestCases{
					name: fmt.Sprintf("keySizeInBytes=%d, derivedKeySize=%d, hkdfHashType=%s, hmacHashType=%s", derivedKeySize, derivedKeySize, hkdfHashType, hmacHashType),
					parameterOpts: aesctrhmac.ParametersOpts{
						KeySizeInBytes:        derivedKeySize,
						DerivedKeySizeInBytes: derivedKeySize,
						HkdfHashType:          hkdfHashType,
						HmacHashType:          hmacHashType,
						HmacTagSizeInBytes:    hmacTagSize,
						SegmentSizeInBytes:    1024,
					},
				})
			}
		}
	}
	return testCases
}

func TestNewParameters(t *testing.T) {
	testCases := getParametersTestCases(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesctrhmac.NewParameters(tc.parameterOpts)
			if err != nil {
				t.Fatalf("NewParameters() err = %v, want nil", err)
			}
			if params.KeySizeInBytes() != tc.parameterOpts.KeySizeInBytes {
				t.Errorf("params.KeySizeInBytes() = %d, want %d", params.KeySizeInBytes(), tc.parameterOpts.KeySizeInBytes)
			}
			if params.DerivedKeySizeInBytes() != tc.parameterOpts.DerivedKeySizeInBytes {
				t.Errorf("params.DerivedKeySizeInBytes() = %d, want %d", params.DerivedKeySizeInBytes(), tc.parameterOpts.DerivedKeySizeInBytes)
			}
			if params.HkdfHashType() != tc.parameterOpts.HkdfHashType {
				t.Errorf("params.HkdfHashType() = %s, want %s", params.HkdfHashType(), tc.parameterOpts.HkdfHashType)
			}
			if params.HmacHashType() != tc.parameterOpts.HmacHashType {
				t.Errorf("params.HmacHashType() = %s, want %s", params.HmacHashType(), tc.parameterOpts.HmacHashType)
			}
			if params.HmacTagSizeInBytes() != tc.parameterOpts.HmacTagSizeInBytes {
				t.Errorf("params.HmacTagSizeInBytes() = %d, want %d", params.HmacTagSizeInBytes(), tc.parameterOpts.HmacTagSizeInBytes)
			}
			if params.SegmentSizeInBytes() != tc.parameterOpts.SegmentSizeInBytes {
				t.Errorf("params.SegmentSizeInBytes() = %d, want %d", params.SegmentSizeInBytes(), tc.parameterOpts.SegmentSizeInBytes)
			}
			if params.HasIDRequirement() {
				t.Errorf("params.HasIDRequirement() = true, want false")
			}

			// Test equality.
			if diff := cmp.Diff(params, params, cmp.AllowUnexported(aesctrhmac.Parameters{})); diff != "" {
				t.Errorf("params.Equal(params) returned unexpected diff (-want +got):\n%s", diff)
			}
			otherParams, err := aesctrhmac.NewParameters(tc.parameterOpts)
			if err != nil {
				t.Fatalf("NewParameters() err = %v, want nil", err)
			}
			if diff := cmp.Diff(params, otherParams, cmp.AllowUnexported(aesctrhmac.Parameters{})); diff != "" {
				t.Errorf("params.Equal(otherParams) returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func mustCreateParameters(t *testing.T, opts aesctrhmac.ParametersOpts) *aesctrhmac.Parameters {
	t.Helper()
	params, err := aesctrhmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", opts, err)
	}
	return params
}

func TestParametersEqual_FalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params1 *aesctrhmac.Parameters
		params2 *aesctrhmac.Parameters
	}{
		{
			name:    "different key size",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
		},
		{
			name:    "different derived key size",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 32, DerivedKeySizeInBytes: 32, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
		},
		{
			name:    "different hkdf hash type",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA512, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
		},
		{
			name:    "different hmac hash type",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA512, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
		},
		{
			name:    "different hmac tag size",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 32, SegmentSizeInBytes: 256}),
		},
		{
			name:    "different ciphertext segment size",
			params1: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 256}),
			params2: mustCreateParameters(t, aesctrhmac.ParametersOpts{KeySizeInBytes: 16, DerivedKeySizeInBytes: 16, HkdfHashType: aesctrhmac.SHA256, HmacHashType: aesctrhmac.SHA256, HmacTagSizeInBytes: 16, SegmentSizeInBytes: 512}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.params1, tc.params2, cmp.AllowUnexported(aesctrhmac.Parameters{})); diff == "" {
				t.Errorf("params1.Equal(params2) = true, want false. Diff: %v", diff)
			}
		})
	}
}

func TestHashType_String(t *testing.T) {
	for _, tc := range []struct {
		hashType aesctrhmac.HashType
		want     string
	}{
		{aesctrhmac.SHA1, "SHA1"},
		{aesctrhmac.SHA256, "SHA256"},
		{aesctrhmac.SHA512, "SHA512"},
		{0, "UNKNOWN"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if diff := cmp.Diff(tc.hashType.String(), tc.want); diff != "" {
				t.Errorf("tc.hashType.String() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
