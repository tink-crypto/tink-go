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

package prfbasedkeyderivation_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
)

func TestKeyderivation_EndToEnd(t *testing.T) {
	// From https://www.rfc-editor.org/rfc/rfc5869#appendix-A.2.
	keyBytes := mustHexDecode(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	derivationSalt := mustHexDecode(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	outputBytes := mustHexDecode(t, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
	prfSalt := mustHexDecode(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	prfParams, err := hkdfprf.NewParameters(len(keyBytes), hkdfprf.SHA256, prfSalt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() err = %v, want nil", err)
	}
	prfKey, err := hkdfprf.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), prfParams)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() err = %v, want nil", err)
	}

	aes128GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	want128AESGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData(outputBytes[:aes128GCMParams.KeySizeInBytes()], insecuresecretdataaccess.Token{}), 0x1234, aes128GCMParams)
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
	want128AESGCMNoPrefixKey, err := aesgcm.NewKey(secretdata.NewBytesFromData(outputBytes[:aes128GCMNoPrefixParams.KeySizeInBytes()], insecuresecretdataaccess.Token{}), 0, aes128GCMNoPrefixParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}

	aes256GCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	want256AESGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData(outputBytes[:aes256GCMParams.KeySizeInBytes()], insecuresecretdataaccess.Token{}), 0x1234, aes256GCMParams)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}

	hmacSHA512Params, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		HashType:       hmac.SHA512,
		TagSizeInBytes: 16,
		Variant:        hmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("hmac.NewParameters() err = %v, want nil", err)
	}
	wantHMACSHA512Key, err := hmac.NewKey(secretdata.NewBytesFromData(outputBytes[:hmacSHA512Params.KeySizeInBytes()], insecuresecretdataaccess.Token{}), hmacSHA512Params, 0x1234)
	if err != nil {
		t.Fatalf("hmac.NewKey() err = %v, want nil", err)
	}

	streamingAEADAES128GCMHKDFParams, err := aesgcmhkdf.NewParameters(aesgcmhkdf.ParametersOpts{
		KeySizeInBytes:        16,
		DerivedKeySizeInBytes: 16,
		HKDFHashType:          aesgcmhkdf.SHA256,
		SegmentSizeInBytes:    4096,
	})
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewParameters() err = %v, want nil", err)
	}
	wantStreamingAEADAES128GCMHKDFKey, err := aesgcmhkdf.NewKey(streamingAEADAES128GCMHKDFParams, secretdata.NewBytesFromData(outputBytes[:streamingAEADAES128GCMHKDFParams.KeySizeInBytes()], insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aesgcmhkdf.NewKey() err = %v, want nil", err)
	}

	ed25519Params, err := ed25519.NewParameters(ed25519.VariantTink)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	wantED25519Key, err := ed25519.NewPrivateKey(secretdata.NewBytesFromData(outputBytes[:32], insecuresecretdataaccess.Token{}), 0x1234, ed25519Params)
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey() err = %v, want nil", err)
	}
	ed25519NoPrefixParams, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	wantED25519KeyNoPrefixKey, err := ed25519.NewPrivateKey(secretdata.NewBytesFromData(outputBytes[:32], insecuresecretdataaccess.Token{}), 0, ed25519NoPrefixParams)
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey() err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		derivedKeyParams key.Parameters
		wantKey          key.Key
		idRequirement    uint32
	}{
		{
			name:             "AES128_GCM",
			derivedKeyParams: aes128GCMParams,
			wantKey:          want128AESGCMKey,
			idRequirement:    0x1234,
		},
		{
			name:             "AES128_GCM_no_prefix",
			derivedKeyParams: aes128GCMNoPrefixParams,
			wantKey:          want128AESGCMNoPrefixKey,
			idRequirement:    0,
		},
		{
			name:             "AES256_GCM",
			derivedKeyParams: aes256GCMParams,
			wantKey:          want256AESGCMKey,
			idRequirement:    0x1234,
		},
		{
			name:             "HMAC_SHA512",
			derivedKeyParams: hmacSHA512Params,
			wantKey:          wantHMACSHA512Key,
			idRequirement:    0x1234,
		},
		{
			name:             "STREAMING_AEAD_AES128_GCM_HKDF_4KB",
			derivedKeyParams: streamingAEADAES128GCMHKDFParams,
			wantKey:          wantStreamingAEADAES128GCMHKDFKey,
			idRequirement:    0,
		},
		{
			name:             "ED25519",
			derivedKeyParams: &ed25519Params,
			wantKey:          wantED25519Key,
			idRequirement:    0x1234,
		},
		{
			name:             "ED25519_no_prefix",
			derivedKeyParams: &ed25519NoPrefixParams,
			wantKey:          wantED25519KeyNoPrefixKey,
			idRequirement:    0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyDerivationParams, err := prfbasedkeyderivation.NewParameters(prfParams, tc.derivedKeyParams)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewParameters() err = %v, want nil", err)
			}
			keyDerivationKey, err := prfbasedkeyderivation.NewKey(keyDerivationParams, prfKey, tc.idRequirement)
			if err != nil {
				t.Fatalf("prfbasedkeyderivation.NewKey() err = %v, want nil", err)
			}

			km := keyset.NewManager()
			keyID, err := km.AddKey(keyDerivationKey)
			if err != nil {
				t.Fatalf("km.AddKey() err = %v, want nil", err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary() err = %v, want nil", err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}

			deriver, err := keyderivation.New(handle)
			if err != nil {
				t.Fatalf("keyderivation.New() err = %v, want nil", err)
			}
			derivedHandle, err := deriver.DeriveKeyset(derivationSalt)
			if err != nil {
				t.Fatalf("DeriveKeyset() err = %v, want nil", err)
			}

			if derivedHandle.Len() != 1 {
				t.Fatalf("derivedHandle.Len() = %d, want 1", derivedHandle.Len())
			}
			entry, err := derivedHandle.Entry(0)
			if err != nil {
				t.Fatalf("derivedHandle.Entry(0) err = %v, want nil", err)
			}
			got, want := entry.Key(), tc.wantKey
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("derived keyset returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
