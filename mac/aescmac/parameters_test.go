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
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/mac/aescmac"
)

func TestNewParametersInvalidKeySize(t *testing.T) {
	for _, keySize := range []int{0, 15, 33} {
		_, err := aescmac.NewParameters(aescmac.ParametersOpts{
			KeySizeInBytes: keySize,
			TagSizeInBytes: 16,
			Variant:        aescmac.VariantTink,
		})
		if err == nil {
			t.Errorf("NewParameters(%d, 16, VariantTink) err = nil, want error", keySize)
		}
	}
}

func TestNewParametersInvalidTagSize(t *testing.T) {
	for _, tagSize := range []int{0, 9, 17} {
		_, err := aescmac.NewParameters(aescmac.ParametersOpts{
			KeySizeInBytes: 16,
			TagSizeInBytes: tagSize,
			Variant:        aescmac.VariantTink,
		})
		if err == nil {
			t.Errorf("NewParameters(16, %d, VariantTink) err = nil, want error", tagSize)
		}
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	_, err := aescmac.NewParameters(aescmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		Variant:        aescmac.VariantUnknown,
	})
	if err == nil {
		t.Errorf("NewParameters(16, 16, VariantUnknown) err = nil, want error")
	}
}

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		keySizeInBytes int
		tagSizeInBytes int
		variant        aescmac.Variant
	}{
		{
			keySizeInBytes: 16,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantTink,
		},
		{
			keySizeInBytes: 32,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantTink,
		},
		{
			keySizeInBytes: 16,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantCrunchy,
		},
		{
			keySizeInBytes: 32,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantCrunchy,
		},
		{
			keySizeInBytes: 16,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantNoPrefix,
		},
		{
			keySizeInBytes: 32,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantNoPrefix,
		},
		{
			keySizeInBytes: 16,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantLegacy,
		},
		{
			keySizeInBytes: 32,
			tagSizeInBytes: 16,
			variant:        aescmac.VariantLegacy,
		},
	} {
		t.Run(fmt.Sprintf("keySizeInBytes=%d,tagSizeInBytes=%d,variant=%s", tc.keySizeInBytes, tc.tagSizeInBytes, tc.variant), func(t *testing.T) {
			params, err := aescmac.NewParameters(aescmac.ParametersOpts{
				KeySizeInBytes: tc.keySizeInBytes,
				TagSizeInBytes: tc.tagSizeInBytes,
				Variant:        tc.variant,
			})
			if err != nil {
				t.Errorf("NewParameters(%d, %d, %v) err = %v, want nil", tc.keySizeInBytes, tc.tagSizeInBytes, tc.variant, err)
			}
			if params.KeySizeInBytes() != tc.keySizeInBytes {
				t.Errorf("params.KeySizeInBytes() = %d, want %d", params.KeySizeInBytes(), tc.keySizeInBytes)
			}
			if params.CryptographicTagSizeInBytes() != tc.tagSizeInBytes {
				t.Errorf("params.CryptographicTagSizeInBytes() = %d, want %d", params.CryptographicTagSizeInBytes(), tc.tagSizeInBytes)
			}
			wantTotalTagSizeInBytes := tc.tagSizeInBytes
			if tc.variant != aescmac.VariantNoPrefix {
				wantTotalTagSizeInBytes += cryptofmt.NonRawPrefixSize
			}
			if got, want := params.TotalTagSizeInBytes(), wantTotalTagSizeInBytes; got != want {
				t.Errorf("params.TotalTagSizeInBytes() = %d, want %d", got, want)
			}
			if params.Variant() != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), tc.variant)
			}
			if params.HasIDRequirement() != (tc.variant != aescmac.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), tc.variant != aescmac.VariantNoPrefix)
			}

			// Test equality.
			if !params.Equal(params) {
				t.Errorf("params.Equal(params) = false, want true")
			}
			otherParams, err := aescmac.NewParameters(aescmac.ParametersOpts{
				KeySizeInBytes: tc.keySizeInBytes,
				TagSizeInBytes: tc.tagSizeInBytes,
				Variant:        tc.variant,
			})
			if err != nil {
				t.Fatalf("NewParameters(%d, %d, %v) err = %v, want nil", tc.keySizeInBytes, tc.tagSizeInBytes, tc.variant, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = false, want true")
			}
		})
	}
}

func mustCreateParameters(t *testing.T, keySizeInBytes, tagSizeInBytes int, variant aescmac.Variant) *aescmac.Parameters {
	t.Helper()
	params, err := aescmac.NewParameters(aescmac.ParametersOpts{
		KeySizeInBytes: keySizeInBytes,
		TagSizeInBytes: tagSizeInBytes,
		Variant:        variant,
	})
	if err != nil {
		t.Fatalf("NewParameters(%d, %d, %v) err = %v, want nil", keySizeInBytes, tagSizeInBytes, variant, err)
	}
	return params
}

func TestEqualFalseIfDifferent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		params1 *aescmac.Parameters
		params2 *aescmac.Parameters
	}{
		{
			name:    "different key size",
			params1: mustCreateParameters(t, 16, 16, aescmac.VariantTink),
			params2: mustCreateParameters(t, 32, 16, aescmac.VariantTink),
		},
		{
			name:    "different tag size",
			params1: mustCreateParameters(t, 16, 16, aescmac.VariantTink),
			params2: mustCreateParameters(t, 16, 10, aescmac.VariantTink),
		},
		{
			name:    "different variant",
			params1: mustCreateParameters(t, 16, 16, aescmac.VariantTink),
			params2: mustCreateParameters(t, 16, 16, aescmac.VariantCrunchy),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.params1.Equal(tc.params2) {
				t.Errorf("params1.Equal(params2) = true, want false")
			}
		})
	}
}

func TestVariantString(t *testing.T) {
	for _, tc := range []struct {
		variant aescmac.Variant
		want    string
	}{
		{
			variant: aescmac.VariantTink,
			want:    "TINK",
		},
		{
			variant: aescmac.VariantCrunchy,
			want:    "CRUNCHY",
		},
		{
			variant: aescmac.VariantNoPrefix,
			want:    "NO_PREFIX",
		},
		{
			variant: aescmac.VariantLegacy,
			want:    "LEGACY",
		},
		{
			variant: aescmac.VariantUnknown,
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
