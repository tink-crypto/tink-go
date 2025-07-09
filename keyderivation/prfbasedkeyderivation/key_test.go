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

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderiver"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/tink"
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
			name:                 "AES-CMAC-PRF_AES-GCM-Tink-WithZeroIDRequirement",
			prfParameters:        aesCMACPRFParams,
			prfKey:               aesCMACPRFKey,
			derivedKeyParameters: derivedKeyParametersTinkPrefix,
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

func TestKeyCreator(t *testing.T) {
	prfParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32) failed: %v", err)
	}

	derivedKeyParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}

	params, err := prfbasedkeyderivation.NewParameters(prfParams, derivedKeyParams)
	if err != nil {
		t.Fatalf("prfbasedkeyderivation.NewParameters(%v, %v) failed: %v", prfParams, derivedKeyParams, err)
	}

	key, err := keygenregistry.CreateKey(params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey(%v, 0) failed: %v", params, err)
	}
	keyDerivationKey, ok := key.(*prfbasedkeyderivation.Key)
	if !ok {
		t.Fatalf("keygenregistry.CreateKey(%v, 0) returned key of type %T, want %T", params, key, (*prfbasedkeyderivation.Key)(nil))
	}

	idRequirement, hasIDRequirement := keyDerivationKey.IDRequirement()
	if hasIDRequirement || idRequirement != 0 {
		t.Errorf("keyDerivationKey.IDRequirement() (%v, %v), want (%v, %v)", idRequirement, hasIDRequirement, 0, true)
	}
	if diff := cmp.Diff(keyDerivationKey.Parameters(), params); diff != "" {
		t.Errorf("keyDerivationKey.Parameters() diff (-want +got):\n%s", diff)
	}

	config := &registryconfig.RegistryConfig{}
	p, err := config.PrimitiveFromKey(key, internalapi.Token{})
	if err != nil {
		t.Fatalf("config.PrimitiveFromKey(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
	}
	keyDeriverPrimitive, ok := p.(keyderiver.KeyDeriver)
	if !ok {
		t.Errorf("config.PrimitiveFromKey(%v, %v) p, _ = %T, want %T", key, internalapi.Token{}, p, (keyderiver.KeyDeriver)(nil))
	}

	// Derive an AESGCM key.
	generatedKey, err := keyDeriverPrimitive.DeriveKey(nil)
	if err != nil {
		t.Fatalf("keyDeriverPrimitive.DeriveKey() err = %v, want nil", err)
	}
	generatedAESGCMKey, ok := generatedKey.(*aesgcm.Key)
	if !ok {
		t.Errorf("keyDeriverPrimitive.DeriveKey() returned key of type %T, want %T", generatedKey, (*aesgcm.Key)(nil))
	}

	// Encrypt/decrypt.
	aeadPrimitive, err := config.PrimitiveFromKey(generatedKey, internalapi.Token{})
	if err != nil {
		t.Fatalf("config.PrimitiveFromKey(%v, %v) err = %v, want nil", generatedAESGCMKey, internalapi.Token{}, err)
	}
	aead, ok := aeadPrimitive.(tink.AEAD)
	if !ok {
		t.Errorf("config.PrimitiveFromKey(%v, %v) p, _ = %T, want %T", generatedAESGCMKey, internalapi.Token{}, p, (tink.AEAD)(nil))
	}
	ciphertext, err := aead.Encrypt([]byte("plaintext"), []byte("associated data"))
	if err != nil {
		t.Fatalf("aead.Encrypt() err = %v, want nil", err)
	}
	plaintext, err := aead.Decrypt(ciphertext, []byte("associated data"))
	if err != nil {
		t.Fatalf("aead.Decrypt() err = %v, want nil", err)
	}
	if diff := cmp.Diff(plaintext, []byte("plaintext")); diff != "" {
		t.Errorf("aead.Decrypt() diff (-want +got):\n%s", diff)
	}
}

func TestKeyCreator_FailsIfUnsupportedParamValues(t *testing.T) {
	unsupportedPRFParams, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}

	derivedKeyParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}

	prfParams, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters(32) failed: %v", err)
	}

	nonDerivableKeyParams, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, 65537, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters() failed: %v", err)
	}

	for _, tc := range []struct {
		name       string
		parameters *prfbasedkeyderivation.Parameters
	}{
		{
			name:       "unsupported PRF parameters",
			parameters: mustCreateParameters(t, &unsupportedPRFParams, derivedKeyParams),
		},
		{
			name:       "unsupported derived key parameters",
			parameters: mustCreateParameters(t, prfParams, nonDerivableKeyParams),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keygenregistry.CreateKey(tc.parameters, 0); err == nil {
				t.Fatalf("keygenregistry.CreateKey(%v, 0) err = nil, want error", tc.parameters)
			} else {
				t.Logf("keygenregistry.CreateKey(%v, 0) err = %v", tc.parameters, err)
			}
		})
	}
}
