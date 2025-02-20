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

package aessiv_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
)

func TestNewParametersInvalidKeySize(t *testing.T) {
	for _, keySize := range []int{1, 15, 17, 31, 33, 47, 49, 63, 65} {
		if _, err := aessiv.NewParameters(keySize, aessiv.VariantTink); err == nil {
			t.Errorf("aessiv.NewParameters(%v, %v) err = nil, want error", keySize, aessiv.VariantTink)
		}
	}
}

func TestNewParametersInvalidVariant(t *testing.T) {
	if _, err := aessiv.NewParameters(32, aessiv.VariantUnknown); err == nil {
		t.Errorf("aessiv.NewParameters(%v, %v) err = nil, want error", 32, aessiv.VariantUnknown)
	}
}

func TestNewParametersWorks(t *testing.T) {
	for _, test := range []struct {
		name    string
		keySize int
		variant aessiv.Variant
	}{
		{
			name:    "256-bit key with Tink prefix",
			keySize: 32,
			variant: aessiv.VariantTink,
		},
		{
			name:    "256-bit key with Crunchy prefix",
			keySize: 32,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "256-bit key with NoPrefix prefix",
			keySize: 32,
			variant: aessiv.VariantNoPrefix,
		},
		{
			name:    "384-bit key with Tink prefix",
			keySize: 48,
			variant: aessiv.VariantTink,
		},
		{
			name:    "384-bit key with Crunchy prefix",
			keySize: 48,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "384-bit key with NoPrefix prefix",
			keySize: 48,
			variant: aessiv.VariantNoPrefix,
		},
		{
			name:    "512-bit key with Tink prefix",
			keySize: 64,
			variant: aessiv.VariantTink,
		},
		{
			name:    "512-bit key with Crunchy prefix",
			keySize: 64,
			variant: aessiv.VariantCrunchy,
		},
		{
			name:    "512-bit key with NoPrefix prefix",
			keySize: 64,
			variant: aessiv.VariantNoPrefix,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params, err := aessiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			if params.HasIDRequirement() != (test.variant != aessiv.VariantNoPrefix) {
				t.Errorf("params.HasIDRequirement() = %v, want %v", params.HasIDRequirement(), (test.variant != aessiv.VariantNoPrefix))
			}
			if params.KeySizeInBytes() != test.keySize {
				t.Errorf("params.KeySizeInBytes()() = %v, want %v", params.KeySizeInBytes(), test.keySize)
			}
			if params.Variant() != test.variant {
				t.Errorf("params.Variant() = %v, want %v", params.Variant(), test.variant)
			}
			otherParams, err := aessiv.NewParameters(test.keySize, test.variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.keySize, test.variant, err)
			}
			if !params.Equal(otherParams) {
				t.Errorf("params.Equal(otherParams) = %v, want true", params.Equal(otherParams))
			}
		})
	}
}

func TestParametersEqualFalseIfDifferent(t *testing.T) {
	for _, test := range []struct {
		name        string
		key1Size    int
		key1Variant aessiv.Variant
		key2Size    int
		key2Variant aessiv.Variant
	}{
		{
			name:        "different key size",
			key1Size:    32,
			key1Variant: aessiv.VariantTink,
			key2Size:    64,
			key2Variant: aessiv.VariantTink,
		},
		{
			name:        "different prefix variant",
			key1Size:    32,
			key1Variant: aessiv.VariantCrunchy,
			key2Size:    32,
			key2Variant: aessiv.VariantTink,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params1, err := aessiv.NewParameters(test.key1Size, test.key1Variant)
			if err != nil {
				t.Fatalf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.key1Size, test.key1Variant, err)
			}
			params2, err := aessiv.NewParameters(test.key2Size, test.key2Variant)
			if err != nil {
				t.Errorf("aessiv.NewParameters(%v, %v) err = %v, want nil", test.key2Size, test.key2Variant, err)
			}
			if params1.Equal(params2) {
				t.Errorf("params.Equal(params2) = %v, want false", params1.Equal(params2))
			}
		})
	}
}
