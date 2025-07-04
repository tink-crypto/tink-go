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

package keyderivers_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/daead/aessiv"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/internal/keyderivers"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf/hmacprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
)

func TestDeriveKey(t *testing.T) {
	// AES-GCM keys.
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes128GCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}), 123, aes128GCMParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}
	aes128GCMNoPrefixParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	aes128GCMNoPrefixKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}), 0, aes128GCMNoPrefixParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}

	// XChaCha20-Poly1305 keys.
	xChaCha20Poly1305Params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err = %v, want nil", err)
	}
	xChaCha20Poly1305Key, err := xchacha20poly1305.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 123, xChaCha20Poly1305Params)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
	}
	xChaCha20Poly1305NoPrefixParams, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err = %v, want nil", err)
	}
	xChaCha20Poly1305NoPrefixKey, err := xchacha20poly1305.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 0, xChaCha20Poly1305NoPrefixParams)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
	}

	// AES-SIV keys.
	aes256SIVParams, err := aessiv.NewParameters(32, aessiv.VariantTink)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aes256SIVKey, err := aessiv.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 123, aes256SIVParams)
	if err != nil {
		t.Fatalf("aessiv.NewKey() err = %v, want nil", err)
	}
	aes256SIVNoPrefixParams, err := aessiv.NewParameters(32, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aes256SIVNoPrefixKey, err := aessiv.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 0, aes256SIVNoPrefixParams)
	if err != nil {
		t.Fatalf("aessiv.NewKey() err = %v, want nil", err)
	}

	// HMAC keys.
	hmacSHA256Tag128Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256Tag128Key, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA256Tag128Params, 123)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA256Tag128NoPrefixParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256Tag128NoPrefixKey, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA256Tag128NoPrefixParams, 0)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA256Tag256Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256Tag256Key, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA256Tag256Params, 123)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA256Tag256NoPrefixParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256Tag256NoPrefixKey, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA256Tag256NoPrefixParams, 0)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA512Tag256Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 64,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA512,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA512Tag256Key, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345012345678901234501234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA512Tag256Params, 123)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA512Tag256NoPrefixParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 64,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA512,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA512Tag256NoPrefixKey, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345012345678901234501234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA512Tag256NoPrefixParams, 0)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA512Tag512Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 64,
		TagSizeInBytes: 64,
		HashType:       hmac.SHA512,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA512Tag512Key, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345012345678901234501234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA512Tag512Params, 123)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}
	hmacSHA512Tag512NoPrefixParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 64,
		TagSizeInBytes: 64,
		HashType:       hmac.SHA512,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA512Tag512NoPrefixKey, err := hmac.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345012345678901234501234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA512Tag512NoPrefixParams, 0)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}

	// PRF keys.
	hkdfPRFSHA256Params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	hkdfPRFSHA256Key, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hkdfPRFSHA256Params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}
	hmacSHA256PRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256PRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA256PRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}
	hmacSHA512PRFParams, err := hmacprf.NewParameters(64, hmacprf.SHA512)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}
	hmacSHA512PRFKey, err := hmacprf.NewKey(secretdata.NewBytesFromData([]byte("0123456789012345012345678901234501234567890123450123456789012345"), insecuresecretdataaccess.Token{}), hmacSHA512PRFParams)
	if err != nil {
		t.Fatalf("hmacprf.NewKey() err = %v, want nil", err)
	}

	// Signature keys.
	ed25519Params, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	ed25519Key, err := ed25519.NewPrivateKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 123, ed25519Params)
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey() err = %v, want nil", err)
	}
	ed25519NoPrefixParams, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	ed25519KeyNoPrefixKey, err := ed25519.NewPrivateKey(secretdata.NewBytesFromData([]byte("01234567890123450123456789012345"), insecuresecretdataaccess.Token{}), 0, ed25519NoPrefixParams)
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey() err = %v, want nil", err)
	}

	// Streaming AEAD keys.
	aesGCMHKDFParams, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HKDFHashType:          aesgcmhkdf.SHA256,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	aesGCMHKDFKey, err := aesgcmhkdf.NewKey(aesGCMHKDFParams, secretdata.NewBytesFromData([]byte("0123456789012345"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewPrivateKey() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name          string
		params        key.Parameters
		idRequirement uint32
		randomBytes   []byte
		wantKey       key.Key
	}{
		{
			name:          "AES128GCM",
			params:        aes128GCMParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345"),
			wantKey:       aes128GCMKey,
		},
		{
			name:          "AES128GCM_longer_key_bytes",
			params:        aes128GCMParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       aes128GCMKey,
		},
		{
			name:          "AES128GCMNoPrefix",
			params:        aes128GCMNoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345"),
			wantKey:       aes128GCMNoPrefixKey,
		},
		{
			name:          "XChaCha20Poly13035",
			params:        xChaCha20Poly1305Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       xChaCha20Poly1305Key,
		},
		{
			name:          "XChaCha20Poly13035_longer_key_bytes",
			params:        xChaCha20Poly1305Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       xChaCha20Poly1305Key,
		},
		{
			name:          "XChaCha20Poly13035NoPrefix",
			params:        xChaCha20Poly1305NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       xChaCha20Poly1305NoPrefixKey,
		},
		{
			name:          "AES256SIV",
			params:        aes256SIVParams,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       aes256SIVKey,
		},
		{
			name:          "AES256SIV_longer_key_bytes",
			params:        aes256SIVParams,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       aes256SIVKey,
		},
		{
			name:          "AES256SIVNoPrefix",
			params:        aes256SIVNoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       aes256SIVNoPrefixKey,
		},
		{
			name:          "HMACSHA256Tag128",
			params:        hmacSHA256Tag128Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hmacSHA256Tag128Key,
		},
		{
			name:          "HMACSHA256Tag128_longer_key_bytes",
			params:        hmacSHA256Tag128Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA256Tag128Key,
		},
		{
			name:          "HMACSHA256Tag128NoPrefix",
			params:        hmacSHA256Tag128NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hmacSHA256Tag128NoPrefixKey,
		},
		{
			name:          "HMACSHA256Tag256",
			params:        hmacSHA256Tag256Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hmacSHA256Tag256Key,
		},
		{
			name:          "HMACSHA256Tag256_longer_key_bytes",
			params:        hmacSHA256Tag256Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA256Tag256Key,
		},
		{
			name:          "HMACSHA256Tag256NoPrefix",
			params:        hmacSHA256Tag256NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hmacSHA256Tag256NoPrefixKey,
		},
		{
			name:          "HMACSHA512Tag256",
			params:        hmacSHA512Tag256Params,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345"),
			wantKey:       hmacSHA512Tag256Key,
		},
		{
			name:          "HMACSHA512Tag256_longer_key_bytes",
			params:        hmacSHA512Tag256Params,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA512Tag256Key,
		},
		{
			name:          "HMACSHA512Tag256NoPrefix",
			params:        hmacSHA512Tag256NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345"),
			wantKey:       hmacSHA512Tag256NoPrefixKey,
		},
		{
			name:          "HMACSHA512Tag512",
			params:        hmacSHA512Tag512Params,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345"),
			wantKey:       hmacSHA512Tag512Key,
		},
		{
			name:          "HMACSHA512Tag512_longer_key_bytes",
			params:        hmacSHA512Tag512Params,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA512Tag512Key,
		},
		{
			name:          "HMACSHA512Tag512NoPrefix",
			params:        hmacSHA512Tag512NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345"),
			wantKey:       hmacSHA512Tag512NoPrefixKey,
		},
		{
			name:          "HKDF_SHA256",
			params:        hkdfPRFSHA256Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hkdfPRFSHA256Key,
		},
		{
			name:          "HKDF_SHA256_longer_key_bytes",
			params:        hkdfPRFSHA256Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hkdfPRFSHA256Key,
		},
		{
			name:          "HMAC_SHA256_PRF",
			params:        hmacSHA256PRFParams,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       hmacSHA256PRFKey,
		},
		{
			name:          "HMAC_SHA256_longer_key_bytes_PRF",
			params:        hmacSHA256PRFParams,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA256PRFKey,
		},
		{
			name:          "HMAC_SHA512_PRF",
			params:        hmacSHA512PRFParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345"),
			wantKey:       hmacSHA512PRFKey,
		},
		{
			name:          "HMAC_SHA512_longer_key_bytes_PRF",
			params:        hmacSHA512PRFParams,
			idRequirement: 123,
			randomBytes:   []byte("0123456789012345012345678901234501234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       hmacSHA512PRFKey,
		},
		{
			name:          "ED25519",
			params:        &ed25519Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       ed25519Key,
		},
		{
			name:          "ED25519_longer_key_bytes",
			params:        &ed25519Params,
			idRequirement: 123,
			randomBytes:   []byte("01234567890123450123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       ed25519Key,
		},
		{
			name:          "ED25519NoPrefix",
			params:        &ed25519NoPrefixParams,
			idRequirement: 0,
			randomBytes:   []byte("01234567890123450123456789012345"),
			wantKey:       ed25519KeyNoPrefixKey,
		},
		{
			name:          "AESGCMHKDF",
			params:        aesGCMHKDFParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345"),
			wantKey:       aesGCMHKDFKey,
		},
		{
			name:          "AESGCMHKDF_longer_key_bytes",
			params:        aesGCMHKDFParams,
			idRequirement: 0,
			randomBytes:   []byte("0123456789012345ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			wantKey:       aesGCMHKDFKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			derivedKey, err := keyderivers.DeriveKey(tc.params, tc.idRequirement, bytes.NewBuffer(tc.randomBytes), insecuresecretdataaccess.Token{})
			if err != nil {
				t.Fatalf("keyderivation.DeriveKey() err = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.wantKey, derivedKey); diff != "" {
				t.Errorf("keyderivation.DeriveKey() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeriveKey_Failures(t *testing.T) {
	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	aes128GCMNoPrefixParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}

	xChaCha20Poly1305Params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err = %v, want nil", err)
	}
	xChaCha20Poly1305NoPrefixParams, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err = %v, want nil", err)
	}

	aes256SIVParams, err := aessiv.NewParameters(32, aessiv.VariantTink)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aes256SIVNoPrefixParams, err := aessiv.NewParameters(32, aessiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}

	hmacSHA256Tag128Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256Tag128NoPrefixParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}

	hkdfPRFSHA256Params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	hmacSHA256PRFParams, err := hmacprf.NewParameters(32, hmacprf.SHA256)
	if err != nil {
		t.Fatalf("hmacprf.NewParameters() err = %v, want nil", err)
	}

	ed25519Params, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	ed25519NoPrefixParams, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name            string
		params          key.Parameters
		idRequirement   uint32
		randomnessBytes []byte
	}{
		{
			name:            "invalid parameters type",
			params:          &stubParams{},
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345"),
		},
		{
			name:            "AES128GCM insufficient random bytes",
			params:          aes128GCMParams,
			idRequirement:   123,
			randomnessBytes: []byte("012345678901234"), // 1 byte short
		},
		{
			name:            "AES128GCM invalid ID requirement",
			params:          aes128GCMNoPrefixParams,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345"),
		},
		{
			name:            "XChaCha20Poly1305 insufficient random bytes",
			params:          xChaCha20Poly1305Params,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "XChaCha20Poly1305 invalid ID requirement",
			params:          xChaCha20Poly1305NoPrefixParams,
			idRequirement:   123,
			randomnessBytes: []byte("01234567890123450123456789012345"),
		},
		{
			name:            "AES-SIV insufficient random bytes",
			params:          aes256SIVParams,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "AES-SIV invalid ID requirement",
			params:          aes256SIVNoPrefixParams,
			idRequirement:   123,
			randomnessBytes: []byte("01234567890123450123456789012345"),
		},
		{
			name:            "HMAC insufficient random bytes",
			params:          hmacSHA256Tag128Params,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "HMAC invalid ID requirement",
			params:          hmacSHA256Tag128NoPrefixParams,
			idRequirement:   123,
			randomnessBytes: []byte("01234567890123450123456789012345"),
		},
		{
			name:            "HKDF PRF insufficient random bytes",
			params:          hkdfPRFSHA256Params,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "HMAC PRF insufficient random bytes",
			params:          hmacSHA256PRFParams,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "ED25519 insufficient random bytes",
			params:          &ed25519Params,
			idRequirement:   123,
			randomnessBytes: []byte("0123456789012345012345678901234"), // 1 byte short
		},
		{
			name:            "ED25519 invalid ID requirement",
			params:          &ed25519NoPrefixParams,
			idRequirement:   123,
			randomnessBytes: []byte("01234567890123450123456789012345"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := keyderivers.DeriveKey(tc.params, tc.idRequirement, bytes.NewBuffer(tc.randomnessBytes), insecuresecretdataaccess.Token{}); err == nil {
				t.Errorf("keyderivers.DeriveKey() err = nil, want error")
			}
		})
	}
}

type stubParams struct {
	hasIDRequirement bool
}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) HasIDRequirement() bool { return p.hasIDRequirement }

func (p *stubParams) Equal(other key.Parameters) bool {
	_, ok := other.(*stubParams)
	return ok
}
