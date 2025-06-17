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

package prfbasedkeyderivation_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
)

type stubParameters struct{}

var _ key.Parameters = (*stubParameters)(nil)

func (p *stubParameters) Equal(other key.Parameters) bool { return false }

func (p *stubParameters) HasIDRequirement() bool { return false }

func TestParametersInvalid(t *testing.T) {
	aesCMACPRF, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	derivedKeyParameters, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	for _, tc := range []struct {
		name                 string
		prfParameters        key.Parameters
		derivedKeyParameters key.Parameters
	}{
		{
			name:                 "nil_prfParameters",
			prfParameters:        nil,
			derivedKeyParameters: derivedKeyParameters,
		},
		{
			name:                 "nil_derivedKeyParameters",
			prfParameters:        &aesCMACPRF,
			derivedKeyParameters: nil,
		},
		{
			name:                 "invalid_prfParameters_type",
			prfParameters:        &stubParameters{},
			derivedKeyParameters: derivedKeyParameters,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prfbasedkeyderivation.NewParameters(tc.prfParameters, tc.derivedKeyParameters); err == nil {
				t.Errorf("prfbasedkeyderivation.NewParameters(%v, %v) succeeded, want error", tc.prfParameters, tc.derivedKeyParameters)
			}
		})
	}
}

func TestParametersValid(t *testing.T) {
	aesCMACPRF, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	hkdfPRF, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte(\"salt\")) failed: %v", err)
	}
	hmacPRF, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(32, hmacprf.SHA256) failed: %v", err)
	}

	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersWithTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}

	for _, tc := range []struct {
		name                 string
		prfParameters        key.Parameters
		derivedKeyParameters key.Parameters
	}{
		{
			name:                 "AES-CMAC-PRF_AES-GCM-NoPrefix",
			prfParameters:        &aesCMACPRF,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
		},
		{
			name:                 "HKDF-PRF_AES-GCM-NoPrefix",
			prfParameters:        hkdfPRF,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
		},
		{
			name:                 "HMAC-PRF_AES-GCM-NoPrefix",
			prfParameters:        hmacPRF,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
		},
		{
			name:                 "AES-CMAC-PRF_AES-GCM-TinkPrefix",
			prfParameters:        &aesCMACPRF,
			derivedKeyParameters: derivedKeyParametersWithTinkPrefix,
		},
		{
			name:                 "HKDF-PRF_AES-GCM-TinkPrefix",
			prfParameters:        hkdfPRF,
			derivedKeyParameters: derivedKeyParametersWithTinkPrefix,
		},
		{
			name:                 "HMAC-PRF_AES-GCM-TinkPrefix",
			prfParameters:        hmacPRF,
			derivedKeyParameters: derivedKeyParametersWithTinkPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := prfbasedkeyderivation.NewParameters(tc.prfParameters, tc.derivedKeyParameters)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", tc.prfParameters, tc.derivedKeyParameters, err)
			}
			if params.Equal(tc.prfParameters) {
				t.Errorf("params.Equal(%v) = true, want false", tc.prfParameters)
			}
			if params.Equal(tc.derivedKeyParameters) {
				t.Errorf("params.Equal(%v) = true, want false", tc.derivedKeyParameters)
			}

			// Test equality with self.
			if !params.Equal(params) {
				t.Errorf("params.Equal(params) = false, want true")
			}

			params2, err := prfbasedkeyderivation.NewParameters(tc.prfParameters, tc.derivedKeyParameters)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", tc.prfParameters, tc.derivedKeyParameters, err)
			}
			if !params.Equal(params2) {
				t.Errorf("params.Equal(params2) = false, want true")
			}

			if params.DerivedKeyParameters() != tc.derivedKeyParameters {
				t.Errorf("params.DerivedKeyParameters() = %v, want %v", params.DerivedKeyParameters(), tc.derivedKeyParameters)
			}
			if params.PRFParameters() != tc.prfParameters {
				t.Errorf("params.PRFParameters() = %v, want %v", params.PRFParameters(), tc.prfParameters)
			}

			if params.HasIDRequirement() != tc.derivedKeyParameters.HasIDRequirement() {
				t.Errorf("params.HasIDRequirement() = true, want false")
			}
		})
	}
}

func TestParametersNotEqual(t *testing.T) {
	aesCMACPRF, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	hkdfPRF, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte(\"salt\")) failed: %v", err)
	}

	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersWithTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}

	params1, err := prfbasedkeyderivation.NewParameters(&aesCMACPRF, derivedKeyParametersNoPrefix)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", &aesCMACPRF, derivedKeyParametersNoPrefix, err)
	}

	// Different PRF parameters.
	params2, err := prfbasedkeyderivation.NewParameters(hkdfPRF, derivedKeyParametersNoPrefix)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", hkdfPRF, derivedKeyParametersNoPrefix, err)
	}
	if params1.Equal(params2) {
		t.Errorf("params1.Equal(params2) = true, want false")
	}

	// Different derived key parameters.
	params3, err := prfbasedkeyderivation.NewParameters(&aesCMACPRF, derivedKeyParametersWithTinkPrefix)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", &aesCMACPRF, derivedKeyParametersWithTinkPrefix, err)
	}
	if params1.Equal(params3) {
		t.Errorf("params1.Equal(params3) = true, want false")
	}
}
