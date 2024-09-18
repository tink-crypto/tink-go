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

package ecdsa_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name      string
		curveType ecdsa.CurveType
		hashType  ecdsa.HashType
		encoding  ecdsa.SignatureEncoding
		variant   ecdsa.Variant
	}{
		{
			name:      "unkown curve type",
			curveType: ecdsa.UnknownCurveType,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "unkown encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.UnknownSignatureEncoding,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "unkown variant",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantUnknown,
		},
		{
			name:      "unkown hash type",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.UnknownHashType,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid curve type value (negative)",
			curveType: -1,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid encoding value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  -1,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid variant value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   -1,
		},
		{
			name:      "invalid hash type value (negative)",
			curveType: ecdsa.NistP256,
			hashType:  -1,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid curve type value (too large)",
			curveType: 10,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid encoding value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  10,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "invalid variant value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   10,
		},
		{
			name:      "invalid hash type value (too large)",
			curveType: ecdsa.NistP256,
			hashType:  10,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP256 with SHA384",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP256 with SHA512",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP384 with SHA256",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP521 with SHA256",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
		{
			name:      "NistP521 with SHA384",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
			variant:   ecdsa.VariantTink,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, tc.variant); err == nil {
				t.Errorf("ecdsa.NewParameters(%v, %v, %v, %v) = nil, want error", tc.curveType, tc.hashType, tc.encoding, tc.variant)
			}
		})
	}
}

func TestNewParameters(t *testing.T) {
	testCases := []struct {
		name      string
		curveType ecdsa.CurveType
		hashType  ecdsa.HashType
		encoding  ecdsa.SignatureEncoding
	}{
		{
			name:      "NistP256 with SHA256 and DER encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA384 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA384 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP384 with SHA512 and DER encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP521 with SHA512 and DER encoding",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.DER,
		},
		{
			name:      "NistP256 with SHA256 and IEEEP1363 encoding",
			curveType: ecdsa.NistP256,
			hashType:  ecdsa.SHA256,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA384 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA384 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA384,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP384 with SHA512 and IEEEP1363 encoding",
			curveType: ecdsa.NistP384,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.IEEEP1363,
		},
		{
			name:      "NistP521 with SHA512 and IEEEP1363 encoding",
			curveType: ecdsa.NistP521,
			hashType:  ecdsa.SHA512,
			encoding:  ecdsa.IEEEP1363,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink, err)
			}
			if got, want := params.CurveType(), tc.curveType; got != want {
				t.Errorf("params.CurveType() = %v, want %v", got, want)
			}
			if got, want := params.HashType(), tc.hashType; got != want {
				t.Errorf("params.HashType() = %v, want %v", got, want)
			}
			if got, want := params.SignatureEncoding(), tc.encoding; got != want {
				t.Errorf("params.SignatureEncoding() = %v, want %v", got, want)
			}
			if got, want := params.Variant(), ecdsa.VariantTink; got != want {
				t.Errorf("params.Variant() = %v, want %v", got, want)
			}
			if got, want := params.HasIDRequirement(), true; got != want {
				t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
			}
			other, err := ecdsa.NewParameters(tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink)
			if err != nil {
				t.Fatalf("ecdsa.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.curveType, tc.hashType, tc.encoding, ecdsa.VariantTink, err)
			}
			if !params.Equals(other) {
				t.Errorf("params.Equals(other) = false, want true")
			}
		})
	}
}
