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

package hmac_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
)

func TestNewParametersInvalidKeySize(t *testing.T) {
	for _, keySize := range []int{0, 15} {
		opts := hmac.ParametersOpts{
			KeySizeInBytes: keySize,
			TagSizeInBytes: 16,
			HashType:       hmac.SHA256,
			Variant:        hmac.VariantTink,
		}
		if _, err := hmac.NewParameters(opts); err == nil {
			t.Errorf("hmac.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidHashType(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		HashType:       hmac.UnknownHashType,
		Variant:        hmac.VariantTink,
	}
	if _, err := hmac.NewParameters(opts); err == nil {
		t.Errorf("hmac.NewParameters(%v) err = nil, want error", opts)
	}
}

func TestNewParametersInvalidTagSizeForHashType(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 9,
		HashType:       hmac.UnknownHashType,
		Variant:        hmac.VariantTink,
	}
	if _, err := hmac.NewParameters(opts); err == nil {
		t.Errorf("hmac.NewParameters(%v) err = nil, want error", opts)
	}

	for _, hash := range []struct {
		hashType          hmac.HashType
		maxTagSizeInBytes int
	}{
		{hmac.SHA1, 20},
		{hmac.SHA224, 28},
		{hmac.SHA256, 32},
		{hmac.SHA384, 48},
		{hmac.SHA512, 64},
	} {
		opts := hmac.ParametersOpts{
			KeySizeInBytes: 16,
			TagSizeInBytes: hash.maxTagSizeInBytes + 1,
			HashType:       hash.hashType,
			Variant:        hmac.VariantTink,
		}
		if _, err := hmac.NewParameters(opts); err == nil {
			t.Errorf("hmac.NewParameters(%v) err = nil, want error", opts)
		}
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	opts := hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantUnknown,
	}
	if _, err := hmac.NewParameters(opts); err == nil {
		t.Errorf("hmac.NewParameters(%v) err = nil, want error", opts)
	}
}

func TestNewParameters(t *testing.T) {
	for _, hash := range []struct {
		hashType          hmac.HashType
		maxTagSizeInBytes int
	}{
		{hmac.SHA1, 20},
		{hmac.SHA224, 28},
		{hmac.SHA256, 32},
		{hmac.SHA384, 48},
		{hmac.SHA512, 64},
	} {
		for _, variant := range []hmac.Variant{hmac.VariantTink, hmac.VariantCrunchy, hmac.VariantNoPrefix, hmac.VariantLegacy} {
			for _, keySize := range []int{16, 32} {
				for _, tagSize := range []int{10, hash.maxTagSizeInBytes} {
					t.Run(fmt.Sprintf("keySizeInBytes=%d,tagSizeInBytes=%d,hashType=%s,variant=%s", keySize, tagSize, hash.hashType, variant), func(t *testing.T) {
						opts := hmac.ParametersOpts{
							KeySizeInBytes: keySize,
							TagSizeInBytes: tagSize,
							HashType:       hash.hashType,
							Variant:        variant,
						}
						params, err := hmac.NewParameters(opts)
						if err != nil {
							t.Errorf("hmac.NewParameters(%v) err = %v, want nil", opts, err)
						}
						if params.KeySizeInBytes() != keySize {
							t.Errorf("params.KeySizeInBytes() = %d, want %d", params.KeySizeInBytes(), keySize)
						}
						if got, want := params.CryptographicTagSizeInBytes(), tagSize; got != want {
							t.Errorf("params.CryptographicTagSizeInBytes() = %d, want %d", got, want)
						}
						if got, want := params.HashType(), hash.hashType; got != want {
							t.Errorf("params.HashType() = %s, want %s", got, want)
						}
						wantTotalTagSizeInBytes := tagSize
						if variant != hmac.VariantNoPrefix {
							wantTotalTagSizeInBytes += cryptofmt.NonRawPrefixSize
						}
						if got, want := params.TotalTagSizeInBytes(), wantTotalTagSizeInBytes; got != want {
							t.Errorf("params.TotalTagSizeInBytes() = %d, want %d", got, want)
						}
						if params.Variant() != variant {
							t.Errorf("params.Variant() = %v, want %v", params.Variant(), variant)
						}
						if params.HasIDRequirement() != (variant != hmac.VariantNoPrefix) {
							t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), variant != hmac.VariantNoPrefix)
						}

						// Test equality.
						if !params.Equal(params) {
							t.Errorf("params.Equal(params) = false, want true")
						}
						otherParams, err := hmac.NewParameters(opts)
						if err != nil {
							t.Fatalf("hmac.NewParameters(%v) err = %v, want nil", opts, err)
						}
						if !params.Equal(otherParams) {
							t.Errorf("params.Equal(otherParams) = false, want true")
						}
					})
				}
			}
		}
	}
}

func mustCreateParameters(t *testing.T, opts hmac.ParametersOpts) *hmac.Parameters {
	t.Helper()
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("hmac.NewParameters(%v) err = %v, want nil", opts, err)
	}
	return params
}

func TestEqualFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params1 *hmac.Parameters
		params2 *hmac.Parameters
	}{
		{
			name: "different key size",
			params1: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			params2: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 32,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
		},
		{
			name: "different tag size",
			params1: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			params2: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 10,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
		},
		{
			name: "different hash type",
			params1: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			params2: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA384,
				Variant:        hmac.VariantTink,
			}),
		},
		{
			name: "different variant",
			params1: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantTink,
			}),
			params2: mustCreateParameters(t, hmac.ParametersOpts{
				KeySizeInBytes: 16,
				TagSizeInBytes: 16,
				HashType:       hmac.SHA256,
				Variant:        hmac.VariantCrunchy,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.params1.Equal(tc.params2) {
				t.Errorf("params1.Equal(params2) = true, want false")
			}
		})
	}
}

func TestHashTypeString(t *testing.T) {
	for _, tc := range []struct {
		hashType hmac.HashType
		want     string
	}{
		{
			hashType: hmac.SHA1,
			want:     "SHA1",
		},
		{
			hashType: hmac.SHA224,
			want:     "SHA224",
		},
		{
			hashType: hmac.SHA256,
			want:     "SHA256",
		},
		{
			hashType: hmac.SHA384,
			want:     "SHA384",
		},
		{
			hashType: hmac.SHA512,
			want:     "SHA512",
		},
		{
			hashType: hmac.UnknownHashType,
			want:     "UNKNOWN",
		},
	} {
		t.Run(tc.hashType.String(), func(t *testing.T) {
			if got := tc.hashType.String(); got != tc.want {
				t.Errorf("tc.hashType.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVariantString(t *testing.T) {
	for _, tc := range []struct {
		variant hmac.Variant
		want    string
	}{
		{
			variant: hmac.VariantTink,
			want:    "TINK",
		},
		{
			variant: hmac.VariantCrunchy,
			want:    "CRUNCHY",
		},
		{
			variant: hmac.VariantNoPrefix,
			want:    "NO_PREFIX",
		},
		{
			variant: hmac.VariantLegacy,
			want:    "LEGACY",
		},
		{
			variant: hmac.VariantUnknown,
			want:    "UNKNOWN",
		},
	} {
		t.Run(tc.variant.String(), func(t *testing.T) {
			if got := tc.variant.String(); got != tc.want {
				t.Errorf("tc.variant.String() = %q, want %q", got, tc.want)
			}
		})
	}
}
