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

package rsassapkcs1_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
)

const (
	f4 = 65537
)

func TestNewParametersInvalidValues(t *testing.T) {
	testCases := []struct {
		name            string
		modulusSizeBits int
		hashType        rsassapkcs1.HashType
		publicExponent  int
		variant         rsassapkcs1.Variant
	}{
		{
			name:            "small public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 - 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "large public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  1 << 31,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "even public exponent",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4 + 1,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown hash",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.UnknownHashType,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
		{
			name:            "unknown variant",
			modulusSizeBits: 2048,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantUnknown,
		},
		{
			name:            "invalid modulus size (too small)",
			modulusSizeBits: 1024,
			hashType:        rsassapkcs1.SHA256,
			publicExponent:  f4,
			variant:         rsassapkcs1.VariantTink,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rsassapkcs1.NewParameters(tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant); err == nil {
				t.Errorf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = nil, want error", tc.modulusSizeBits, tc.hashType, tc.publicExponent, tc.variant)
			}
		})
	}
}

func TestNewParameters(t *testing.T) {
	for _, hashType := range []rsassapkcs1.HashType{rsassapkcs1.SHA256, rsassapkcs1.SHA384, rsassapkcs1.SHA512} {
		for _, variant := range []rsassapkcs1.Variant{rsassapkcs1.VariantTink, rsassapkcs1.VariantCrunchy, rsassapkcs1.VariantLegacy, rsassapkcs1.VariantNoPrefix} {
			for _, modulusSizeBits := range []int{2048, 3072, 4096} {
				for _, publicExponent := range []int{f4, 1<<31 - 1} {
					t.Run(fmt.Sprintf("modulusSizeBits:%v_hashType:%v_publicExponent:%v_variant:%v", modulusSizeBits, hashType, publicExponent, variant), func(t *testing.T) {
						params, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if got, want := params.ModulusSizeBits(), modulusSizeBits; got != want {
							t.Errorf("params.ModulusSizeBits() = %v, want %v", got, want)
						}
						if got, want := params.HashType(), hashType; got != want {
							t.Errorf("params.HashType() = %v, want %v", got, want)
						}
						if got, want := params.PublicExponent(), publicExponent; got != want {
							t.Errorf("params.PublicExponent() = %v, want %v", got, want)
						}
						if got, want := params.Variant(), variant; got != want {
							t.Errorf("params.Variant() = %v, want %v", got, want)
						}
						if got, want := params.HasIDRequirement(), variant != rsassapkcs1.VariantNoPrefix; got != want {
							t.Errorf("params.HasIDRequirement() = %v, want %v", got, want)
						}
						other, err := rsassapkcs1.NewParameters(modulusSizeBits, hashType, publicExponent, variant)
						if err != nil {
							t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", modulusSizeBits, hashType, publicExponent, variant, err)
						}
						if !params.Equals(other) {
							t.Errorf("params.Equals(other) = false, want true")
						}
					})
				}
			}
		}
	}
}

type testParams struct {
	modulusSizeBits int
	hashType        rsassapkcs1.HashType
	publicExponent  int
	variant         rsassapkcs1.Variant
}

func TestNewParametersDifferentParameters(t *testing.T) {
	for _, tc := range []struct {
		name string
		this testParams
		that testParams
	}{
		{
			name: "different modulus size",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 3072,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different hash type",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA384,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different public exponent",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantTink,
			},
		},
		{
			name: "different variant",
			this: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  f4,
				variant:         rsassapkcs1.VariantTink,
			},
			that: testParams{
				modulusSizeBits: 2048,
				hashType:        rsassapkcs1.SHA256,
				publicExponent:  1<<31 - 1,
				variant:         rsassapkcs1.VariantNoPrefix,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			this, err := rsassapkcs1.NewParameters(tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.this.modulusSizeBits, tc.this.hashType, tc.this.publicExponent, tc.this.variant, err)
			}
			that, err := rsassapkcs1.NewParameters(tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant)
			if err != nil {
				t.Fatalf("rsassapkcs1.NewParameters(%v, %v, %v, %v) = %v, want nil", tc.that.modulusSizeBits, tc.that.hashType, tc.that.publicExponent, tc.that.variant, err)
			}
			if this.Equals(that) {
				t.Errorf("this.Equals(that) = true, want false")
			}
		})
	}
}
