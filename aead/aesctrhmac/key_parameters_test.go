// Copyright 2024 Google LLC
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

	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
)

func TestNewParametersInvalidAESKeySize(t *testing.T) {
	for _, keySize := range []int{1, 15, 17, 31, 33} {
		opts := aesctrhmac.ParametersOpts{
			AESKeySizeInBytes:  keySize,
			HMACKeySizeInBytes: 16,
			IVSizeInBytes:      12,
			TagSizeInBytes:     16,
			HashType:           aesctrhmac.SHA256,
			Variant:            aesctrhmac.VariantTink,
		}
		if _, err := aesctrhmac.NewParameters(opts); err == nil {
			t.Errorf("aesctrhmac.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidIVSize(t *testing.T) {
	for _, ivSize := range []int{11, 17} {
		opts := aesctrhmac.ParametersOpts{
			AESKeySizeInBytes:  16,
			HMACKeySizeInBytes: 16,
			IVSizeInBytes:      ivSize,
			TagSizeInBytes:     16,
			HashType:           aesctrhmac.SHA256,
			Variant:            aesctrhmac.VariantTink,
		}
		if _, err := aesctrhmac.NewParameters(opts); err == nil {
			t.Errorf("aesctrhmac.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidHMACKeySize(t *testing.T) {
	for _, hmacKeySize := range []int{1, 15} {
		opts := aesctrhmac.ParametersOpts{
			AESKeySizeInBytes:  16,
			HMACKeySizeInBytes: hmacKeySize,
			IVSizeInBytes:      12,
			TagSizeInBytes:     16,
			HashType:           aesctrhmac.SHA256,
			Variant:            aesctrhmac.VariantTink,
		}
		if _, err := aesctrhmac.NewParameters(opts); err == nil {
			t.Errorf("aesctrhmac.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidTagSize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType aesctrhmac.HashType
		tagSize  int
	}{
		{
			name:     "SHA1",
			hashType: aesctrhmac.SHA1,
			tagSize:  21,
		},
		{
			name:     "SHA224",
			hashType: aesctrhmac.SHA224,
			tagSize:  29,
		},
		{
			name:     "SHA256",
			hashType: aesctrhmac.SHA256,
			tagSize:  33,
		},
		{
			name:     "SHA384",
			hashType: aesctrhmac.SHA384,
			tagSize:  49,
		},
		{
			name:     "SHA512",
			hashType: aesctrhmac.SHA512,
			tagSize:  65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     tc.tagSize,
				HashType:           tc.hashType,
				Variant:            aesctrhmac.VariantTink,
			}
			if _, err := aesctrhmac.NewParameters(opts); err == nil {
				t.Errorf("aesctrhmac.NewParameters(%v) err = nil, want error", opts)
			}
		})
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	opts := aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 16,
		IVSizeInBytes:      12,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantUnknown,
	}
	if _, err := aesctrhmac.NewParameters(opts); err == nil {
		t.Errorf("aesctrhmac.NewParameters(%v) err = nil, want error", opts)
	}
}

type paramsTestVector struct {
	name       string
	paramsOpts aesctrhmac.ParametersOpts
}

func paramsTestVectors() []paramsTestVector {
	testVectors := []paramsTestVector{}
	for _, keySize := range []int{16, 24, 32} {
		for _, hmacKeySize := range []int{16, 32} {
			for _, ivSize := range []int{12, 16} {
				for _, variant := range []aesctrhmac.Variant{aesctrhmac.VariantTink, aesctrhmac.VariantCrunchy, aesctrhmac.VariantNoPrefix} {
					testVectors = append(testVectors, paramsTestVector{
						name: fmt.Sprintf("AES%d-CTR-HMAC-%d-iv%d-tag%d-%s-%s", keySize, hmacKeySize, ivSize, 20, aesctrhmac.SHA1, variant),
						paramsOpts: aesctrhmac.ParametersOpts{
							AESKeySizeInBytes:  keySize,
							HMACKeySizeInBytes: hmacKeySize,
							IVSizeInBytes:      ivSize,
							TagSizeInBytes:     20,
							HashType:           aesctrhmac.SHA1,
							Variant:            variant,
						},
					})
					testVectors = append(testVectors, paramsTestVector{
						name: fmt.Sprintf("AES%d-CTR-HMAC-%d-iv%d-tag%d-%s-%s", keySize, hmacKeySize, ivSize, 28, aesctrhmac.SHA224, variant),
						paramsOpts: aesctrhmac.ParametersOpts{
							AESKeySizeInBytes:  keySize,
							HMACKeySizeInBytes: hmacKeySize,
							IVSizeInBytes:      ivSize,
							TagSizeInBytes:     28,
							HashType:           aesctrhmac.SHA224,
							Variant:            variant,
						},
					})
					testVectors = append(testVectors, paramsTestVector{
						name: fmt.Sprintf("AES%d-CTR-HMAC-%d-iv%d-tag%d-%s-%s", keySize, hmacKeySize, ivSize, 32, aesctrhmac.SHA256, variant),
						paramsOpts: aesctrhmac.ParametersOpts{
							AESKeySizeInBytes:  keySize,
							HMACKeySizeInBytes: hmacKeySize,
							IVSizeInBytes:      ivSize,
							TagSizeInBytes:     32,
							HashType:           aesctrhmac.SHA256,
							Variant:            variant,
						},
					})
					testVectors = append(testVectors, paramsTestVector{
						name: fmt.Sprintf("AES%d-CTR-HMAC-%d-iv%d-tag%d-%s-%s", keySize, hmacKeySize, ivSize, 48, aesctrhmac.SHA384, variant),
						paramsOpts: aesctrhmac.ParametersOpts{
							AESKeySizeInBytes:  keySize,
							HMACKeySizeInBytes: hmacKeySize,
							IVSizeInBytes:      ivSize,
							TagSizeInBytes:     48,
							HashType:           aesctrhmac.SHA384,
							Variant:            variant,
						},
					})
					testVectors = append(testVectors, paramsTestVector{
						name: fmt.Sprintf("AES%d-CTR-HMAC-%d-iv%d-tag%d-%s-%s", keySize, hmacKeySize, ivSize, 64, aesctrhmac.SHA512, variant),
						paramsOpts: aesctrhmac.ParametersOpts{
							AESKeySizeInBytes:  keySize,
							HMACKeySizeInBytes: hmacKeySize,
							IVSizeInBytes:      ivSize,
							TagSizeInBytes:     64,
							HashType:           aesctrhmac.SHA512,
							Variant:            variant,
						},
					})
				}
			}
		}
	}
	return testVectors
}

func TestNewParametersWorks(t *testing.T) {
	for _, tc := range paramsTestVectors() {
		t.Run(tc.name, func(t *testing.T) {
			params, err := aesctrhmac.NewParameters(tc.paramsOpts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", tc.paramsOpts, err)
			}
			if params.HasIDRequirement() != (tc.paramsOpts.Variant != aesctrhmac.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (tc.paramsOpts.Variant != aesctrhmac.VariantNoPrefix))
			}
			if params.AESKeySizeInBytes() != tc.paramsOpts.AESKeySizeInBytes {
				t.Errorf("params.AESKeySizeInBytes() = %v, want %v", params.AESKeySizeInBytes(), tc.paramsOpts.AESKeySizeInBytes)
			}
			if params.HMACKeySizeInBytes() != tc.paramsOpts.HMACKeySizeInBytes {
				t.Errorf("params.HMACKeySizeInBytes() = %v, want %v", params.HMACKeySizeInBytes(), tc.paramsOpts.HMACKeySizeInBytes)
			}
			if params.TagSizeInBytes() != tc.paramsOpts.TagSizeInBytes {
				t.Errorf("params.TagSizeInBytes() = %v, want %d", params.TagSizeInBytes(), tc.paramsOpts.TagSizeInBytes)
			}
			if params.IVSizeInBytes() != tc.paramsOpts.IVSizeInBytes {
				t.Errorf("params.IVSizeInBytes() = %v, want %d", params.IVSizeInBytes(), tc.paramsOpts.IVSizeInBytes)
			}
			if params.Variant() != tc.paramsOpts.Variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), tc.paramsOpts.Variant)
			}
			otherParams, err := aesctrhmac.NewParameters(tc.paramsOpts)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", tc.paramsOpts, err)
			}
			if !params.Equals(otherParams) {
				t.Errorf("params.Equals(otherParams) = %v, want true", params.Equals(otherParams))
			}
		})
	}
}

func TestParametersEqualsFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts1 aesctrhmac.ParametersOpts
		opts2 aesctrhmac.ParametersOpts
	}{
		{
			name: "different AES key size",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  32,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name: "different HMAC key size",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 32,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name: "different IV size",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      16,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name: "different tag size",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     20,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name: "different hash",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA224,
				Variant:            aesctrhmac.VariantTink,
			},
		},
		{
			name: "different vairant",
			opts1: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantTink,
			},
			opts2: aesctrhmac.ParametersOpts{
				AESKeySizeInBytes:  16,
				HMACKeySizeInBytes: 16,
				IVSizeInBytes:      12,
				TagSizeInBytes:     16,
				HashType:           aesctrhmac.SHA256,
				Variant:            aesctrhmac.VariantCrunchy,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params1, err := aesctrhmac.NewParameters(tc.opts1)
			if err != nil {
				t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", tc.opts1, err)
			}
			params2, err := aesctrhmac.NewParameters(tc.opts2)
			if err != nil {
				t.Errorf("aesctrhmac.NewParameters(%v) err = %v, want nil", tc.opts2, err)
			}
			if params1.Equals(params2) {
				t.Errorf("params.Equals(params2) = %v, want false", params1.Equals(params2))
			}
		})
	}
}
