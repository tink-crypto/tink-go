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
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (p *stubKey) Equal(other key.Key) bool { return false }

func (p *stubKey) HasIDRequirement() bool { return false }

func (p *stubKey) Parameters() key.Parameters { return nil }

func (p *stubKey) IDRequirement() (uint32, bool) { return 0, false }

func TestNewKey_Invalid(t *testing.T) {
	// PRF keys.
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() failed: %v", err)
	}
	aesCMACPRFParams := aesCMACPRFKey.Parameters().(*aescmacprf.Parameters)

	hmacPRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(32, hmacprf.SHA256) failed: %v", err)
	}
	hmacPRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), insecuresecretdataaccess.Token{}), hmacPRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() failed: %v", err)
	}

	// Derived key parameters.
	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
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
		prfKey               key.Key
		derivedKeyParameters key.Parameters
		idRequirement        uint32
	}{
		{
			name:                 "nil_prfKey",
			prfParameters:        aesCMACPRFParams,
			prfKey:               nil,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
		{
			name:                 "different_prfKey_type",
			prfParameters:        aesCMACPRFParams,
			prfKey:               hmacPRFKey,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
		{
			name:                 "invalid_idRequirement",
			prfParameters:        aesCMACPRFParams,
			prfKey:               aesCMACPRFKey,
			derivedKeyParameters: derivedKeyParametersTinkPrefix,
			idRequirement:        0,
		},
		{
			name:                 "invalid_idRequirement2",
			prfParameters:        aesCMACPRFParams,
			prfKey:               aesCMACPRFKey,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        1234,
		},
		{
			name:                 "invalid_prfKey_type",
			prfParameters:        aesCMACPRFParams,
			prfKey:               &stubKey{},
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := prfbasedkeyderivation.NewParameters(tc.prfParameters, tc.derivedKeyParameters)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", tc.prfParameters, tc.derivedKeyParameters, err)
			}
			if _, err := prfbasedkeyderivation.NewKey(params, tc.prfKey, tc.idRequirement); err == nil {
				t.Errorf("prfbasedkeyderivation.NewKey(%v, %v, %v) succeeded, want error", params, tc.prfKey, tc.idRequirement)
			}
		})
	}
}

func TestNewKey_Valid(t *testing.T) {
	// PRF keys.
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() failed: %v", err)
	}
	aesCMACPRFParams := aesCMACPRFKey.Parameters().(*aescmacprf.Parameters)

	hkdfPRFParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte(\"salt\")) failed: %v", err)
	}
	hkdfPRFKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), insecuresecretdataaccess.Token{}), hkdfPRFParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() failed: %v", err)
	}

	keyBytes3, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		t.Fatalf("secretdata.NewBytesFromRand(32) failed: %v", err)
	}
	hmacPRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters(32, hmacprf.SHA256) failed: %v", err)
	}
	hmacPRFKey, err := hmacprf.NewKey(keyBytes3, hmacPRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() failed: %v", err)
	}

	// Derived key parameters.
	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
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
		prfKey               key.Key
		derivedKeyParameters key.Parameters
		idRequirement        uint32
	}{
		{
			name:                 "AES-CMAC-PRF_AES-GCM-NoPrefix",
			prfParameters:        aesCMACPRFParams,
			prfKey:               aesCMACPRFKey,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
		{
			name:                 "HKDF-PRF_AES-GCM-NoPrefix",
			prfParameters:        hkdfPRFParams,
			prfKey:               hkdfPRFKey,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
		{
			name:                 "HMAC-PRF_AES-GCM-NoPrefix",
			prfParameters:        hmacPRFParams,
			prfKey:               hmacPRFKey,
			derivedKeyParameters: derivedKeyParametersNoPrefix,
			idRequirement:        0,
		},
		{
			name:                 "AES-CMAC-PRF_AES-GCM-Tink",
			prfParameters:        aesCMACPRFParams,
			prfKey:               aesCMACPRFKey,
			derivedKeyParameters: derivedKeyParametersTinkPrefix,
			idRequirement:        0x1234,
		},
		{
			name:                 "HKDF-PRF_AES-GCM-Tink",
			prfParameters:        hkdfPRFParams,
			prfKey:               hkdfPRFKey,
			derivedKeyParameters: derivedKeyParametersTinkPrefix,
			idRequirement:        0x1234,
		},
		{
			name:                 "HMAC-PRF_AES-GCM-Tink",
			prfParameters:        hmacPRFParams,
			prfKey:               hmacPRFKey,
			derivedKeyParameters: derivedKeyParametersTinkPrefix,
			idRequirement:        0x1234,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := prfbasedkeyderivation.NewParameters(tc.prfParameters, tc.derivedKeyParameters)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", tc.prfParameters, tc.derivedKeyParameters, err)
			}
			key, err := prfbasedkeyderivation.NewKey(params, tc.prfKey, tc.idRequirement)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewKey(%v, %v, %v) failed: %v", params, tc.prfKey, tc.idRequirement, err)
			}
			if !key.Parameters().Equal(params) {
				t.Errorf("key.Parameters() = %v, want %v", key.Parameters(), params)
			}
			if !key.PRFKey().Equal(tc.prfKey) {
				t.Errorf("key.PRFKey() = %v, want %v", key.PRFKey(), tc.prfKey)
			}

			idRequirement, required := key.IDRequirement()
			if required != tc.derivedKeyParameters.HasIDRequirement() {
				t.Errorf("key.IDRequirement() = %v, want %v", required, tc.derivedKeyParameters.HasIDRequirement())
			}
			if idRequirement != tc.idRequirement {
				t.Errorf("key.IDRequirement() = %v, want %v", idRequirement, tc.idRequirement)
			}

			if !key.Equal(key) {
				t.Errorf("key.Equal(key) = false, want true")
			}
			key2, err := prfbasedkeyderivation.NewKey(params, tc.prfKey, tc.idRequirement)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewKey(%v, %v, %v) failed: %v", params, tc.prfKey, tc.idRequirement, err)
			}
			if !key.Equal(key2) {
				t.Errorf("key.Equal(key2) = false, want true")
			}
		})
	}
}

func mustCreateKey(t *testing.T, prfParameters key.Parameters, prfKey key.Key, derivedKeyParameters key.Parameters, idRequirement uint32) *prfbasedkeyderivation.Key {
	t.Helper()
	params, err := prfbasedkeyderivation.NewParameters(prfParameters, derivedKeyParameters)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", prfParameters, derivedKeyParameters, err)
	}
	key, err := prfbasedkeyderivation.NewKey(params, prfKey, idRequirement)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewKey(%v, %v, %v) failed: %v", params, prfKey, idRequirement, err)
	}
	return key
}

func TestKeyNotEqual(t *testing.T) {
	// PRF keys.
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewKey() failed: %v", err)
	}
	aesCMACPRFParams := aesCMACPRFKey.Parameters().(*aescmacprf.Parameters)

	hkdfPRFParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32, hkdfprf.SHA25, []byte(\"salt\")) failed: %v", err)
	}
	hkdfPRFKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), insecuresecretdataaccess.Token{}), hkdfPRFParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() failed: %v", err)
	}

	// Derived key parameters.
	derivedKeyParametersNoPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	derivedKeyParametersTinkPrefix, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		key1 *prfbasedkeyderivation.Key
		key2 key.Key
	}{
		{
			name: "different_key_types",
			key1: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersNoPrefix, 0),
			key2: &stubKey{},
		},
		{
			name: "different_prfParameters_and_key",
			key1: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersNoPrefix, 0),
			key2: mustCreateKey(t, hkdfPRFParams, hkdfPRFKey, derivedKeyParametersNoPrefix, 0),
		},
		{
			name: "different_derivedKeyParameters",
			key1: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersNoPrefix, 0),
			key2: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersTinkPrefix, 1234),
		},
		{
			name: "different_idRequirement",
			key1: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersTinkPrefix, 1234),
			key2: mustCreateKey(t, aesCMACPRFParams, aesCMACPRFKey, derivedKeyParametersTinkPrefix, 5678),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key1.Equal(tc.key2) {
				t.Errorf("tc.key1.Equal(tc.key2) = true, want false")
			}
		})
	}
}
