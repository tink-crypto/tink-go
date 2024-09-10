// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ed25519_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
)

func TestNewParameters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant ed25519.Variant
	}{
		{
			name:    "tink",
			variant: ed25519.VariantTink,
		},
		{
			name:    "legacy",
			variant: ed25519.VariantLegacy,
		},
		{
			name:    "crunchy",
			variant: ed25519.VariantCrunchy,
		},
		{
			name:    "no prefix",
			variant: ed25519.VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ed25519.NewParameters(tc.variant)
			if err != nil {
				t.Errorf("ed25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			if got := params.Variant(); got != tc.variant {
				t.Errorf("params.Variant() = %v, want %v", got, tc.variant)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		if _, err := ed25519.NewParameters(ed25519.VariantUnknown); err == nil {
			t.Errorf("ed25519.NewParameters(%v) err = nil, want error", ed25519.VariantUnknown)
		}
	})
}

func TestParametersHasIDRequirement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		variant ed25519.Variant
		want    bool
	}{
		{
			name:    "tink",
			variant: ed25519.VariantTink,
			want:    true,
		},
		{
			name:    "legacy",
			variant: ed25519.VariantLegacy,
			want:    true,
		},
		{
			name:    "crunchy",
			variant: ed25519.VariantCrunchy,
			want:    true,
		},
		{
			name:    "no prefix",
			variant: ed25519.VariantNoPrefix,
			want:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ed25519.NewParameters(tc.variant)
			if err != nil {
				t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", tc.variant, err)
			}
			if got := params.HasIDRequirement(); got != tc.want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParametersEquals(t *testing.T) {
	tinkVariant, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantTink, err)
	}
	legacyVariant, err := ed25519.NewParameters(ed25519.VariantLegacy)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want	 nil", ed25519.VariantLegacy, err)
	}
	crunchyVariant, err := ed25519.NewParameters(ed25519.VariantCrunchy)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want nil", ed25519.VariantCrunchy, err)
	}
	noPrefixVariant, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(%v) err = %v, want	 nil", ed25519.VariantNoPrefix, err)
	}

	for _, params := range []ed25519.Parameters{tinkVariant, legacyVariant, crunchyVariant, noPrefixVariant} {
		if !params.Equals(&params) {
			t.Errorf("params.Equals(params) = false, want true")
		}
	}

	for _, tc := range []struct {
		name         string
		firstParams  ed25519.Parameters
		secondParams ed25519.Parameters
		want         bool
	}{
		{
			name:         "tink vs legacy",
			firstParams:  tinkVariant,
			secondParams: legacyVariant,
		},
		{
			name:         "tink vs crunchy",
			firstParams:  tinkVariant,
			secondParams: crunchyVariant,
		},
		{
			name:         "tink vs no prefix",
			firstParams:  tinkVariant,
			secondParams: noPrefixVariant,
		},
		{
			name:         "legacy vs crunchy",
			firstParams:  legacyVariant,
			secondParams: crunchyVariant,
		},
		{
			name:         "legacy vs no prefix",
			firstParams:  legacyVariant,
			secondParams: noPrefixVariant,
		},
		{
			name:         "crunchy vs no prefix",
			firstParams:  crunchyVariant,
			secondParams: noPrefixVariant,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.firstParams.Equals(&tc.secondParams) {
				t.Errorf("tc.firstParams.Equals(&tc.secondParams) = true, want false")
			}
		})
	}
}
