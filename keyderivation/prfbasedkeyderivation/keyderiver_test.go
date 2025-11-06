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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyderivation/prfbasedkeyderivation"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/prf/aescmacprf"
	"github.com/tink-crypto/tink-go/v2/prf/hkdfprf"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestNewKeyDeriver_Fails(t *testing.T) {
	aesCMACPRF, err := aescmacprf.NewParameters(32)
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}
	aesCMACPRFKey, err := aescmacprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}))
	if err != nil {
		t.Fatalf("aescmacprf.NewParameters(32) failed: %v", err)
	}

	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	prfBasedKeyDerivationParameters, err := prfbasedkeyderivation.NewParameters(&aesCMACPRF, aesGCMParams)
	if err != nil {
		t.Fatalf("NewParameters() failed: %v", err)
	}
	prfBasedKeyDerivationKey, err := prfbasedkeyderivation.NewKey(prfBasedKeyDerivationParameters, aesCMACPRFKey, 1234)
	if err != nil {
		t.Fatalf("NewParameters() failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  *prfbasedkeyderivation.Key
	}{
		{
			name: "nil key",
			key:  nil,
		},
		{
			name: "invalid key",
			key:  &prfbasedkeyderivation.Key{},
		},
		{
			name: "non HKDF PRF key",
			key:  prfBasedKeyDerivationKey,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prfbasedkeyderivation.NewKeyDeriver(tc.key, internalapi.Token{}); err == nil {
				t.Errorf("prfbasedkeyderivation.NewKeyDeriver(%v) succeeded, want error", tc.key)
			}
		})
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) failed: %v", s, err)
	}
	return b
}

func TestDeriveKey(t *testing.T) {
	hkdfPRFSHA256Params, err := hkdfprf.NewParameters(32, hkdfprf.SHA256, []byte("salt"))
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() failed: %v", err)
	}
	hkdfPRFSHA256Key, err := hkdfprf.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), hkdfPRFSHA256Params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() failed: %v", err)
	}

	prfs := []struct {
		name string
		key  key.Key
	}{
		{
			name: "HKDF_SHA256",
			key:  hkdfPRFSHA256Key,
		},
	}

	// Derivation names match KEY_TEMPLATE_NAMES in
	// https://github.com/tink-crypto/tink-cross-lang-tests/blob/main/cross_language/cross_language/util/utilities.py
	derivations := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AES128_GCM",
			template: aead.AES128GCMKeyTemplate(),
		},
		{
			name:     "AES256_GCM",
			template: aead.AES256GCMKeyTemplate(),
		},
		{
			name:     "AES256_GCM_RAW",
			template: aead.AES256GCMNoPrefixKeyTemplate(),
		},
		{
			name:     "XCHACHA20_POLY1305",
			template: aead.XChaCha20Poly1305KeyTemplate(),
		},
		{
			name:     "AES256_SIV",
			template: daead.AESSIVKeyTemplate(),
		},
		{
			name:     "HMAC_SHA256_128BITTAG",
			template: mac.HMACSHA256Tag128KeyTemplate(),
		},
		{
			name:     "HMAC_SHA256_256BITTAG",
			template: mac.HMACSHA256Tag256KeyTemplate(),
		},
		{
			name:     "HMAC_SHA512_256BITTAG",
			template: mac.HMACSHA512Tag256KeyTemplate(),
		},
		{
			name:     "HMAC_SHA512_512BITTAG",
			template: mac.HMACSHA512Tag512KeyTemplate(),
		},
		{
			name:     "HKDF_SHA256",
			template: prf.HKDFSHA256PRFKeyTemplate(),
		},
		{
			name:     "HMAC_SHA256_PRF",
			template: prf.HMACSHA256PRFKeyTemplate(),
		},
		{
			name:     "HMAC_SHA512_PRF",
			template: prf.HMACSHA512PRFKeyTemplate(),
		},
		{
			name:     "ED25519",
			template: signature.ED25519KeyTemplate(),
		},
		// TODO(b/425280769,b/426483477): Add streaming AEAD key templates when key/parameters
		// are available.
	}
	salts := [][]byte{nil, []byte("salt")}
	for _, prf := range prfs {
		for _, der := range derivations {
			for _, salt := range salts {
				name := fmt.Sprintf("%s_%s", prf.name, der.name)
				if salt != nil {
					name += "_with_salt"
				}
				t.Run(name, func(t *testing.T) {
					derParams, err := protoserialization.ParseParameters(der.template)
					if err != nil {
						t.Fatalf("protoserialization.ParseParameters() failed: %v", err)
					}
					prfBasedKeyDerivationParameters, err := prfbasedkeyderivation.NewParameters(prf.key.Parameters(), derParams)
					if err != nil {
						t.Fatalf("NewParameters() failed: %v", err)
					}

					idRequirement := uint32(1234)
					if !prfBasedKeyDerivationParameters.HasIDRequirement() {
						idRequirement = 0
					}
					prfBasedKeyDerivationKey, err := prfbasedkeyderivation.NewKey(prfBasedKeyDerivationParameters, prf.key, idRequirement)
					if err != nil {
						t.Fatalf("NewParameters() failed: %v", err)
					}

					d, err := prfbasedkeyderivation.NewKeyDeriver(prfBasedKeyDerivationKey, internalapi.Token{})
					if err != nil {
						t.Fatalf("prfbasedkeyderivation.NewKeyDeriver() err = %v, want nil", err)
					}

					if _, err := d.DeriveKey(salt); err != nil {
						t.Errorf("DeriveKey() err = %v, want nil", err)
					}
				})
			}
		}
	}
}

func mustCreateAESGCMParams(t *testing.T, opts aesgcm.ParametersOpts) *aesgcm.Parameters {
	t.Helper()
	params, err := aesgcm.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() failed: %v", err)
	}
	return params
}

func mustCreateAESGCMKey(t *testing.T, keyBytes []byte, params *aesgcm.Parameters, idRequirement uint32) key.Key {
	t.Helper()
	key, err := aesgcm.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), idRequirement, params)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() failed: %v", err)
	}
	return key
}

func mustCreateHMACParameters(t *testing.T, opts hmac.ParametersOpts) *hmac.Parameters {
	t.Helper()
	params, err := hmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("hmac.NewParameters() failed: %v", err)
	}
	return params
}

func mustCreateHMACKey(t *testing.T, keyBytes []byte, params *hmac.Parameters, idRequirement uint32) key.Key {
	t.Helper()
	key, err := hmac.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), params, idRequirement)
	if err != nil {
		t.Fatalf("hmac.NewKey() failed: %v", err)
	}
	return key
}

func mustCreateHKDFPRFKey(t *testing.T, keyBytes []byte, salt []byte) key.Key {
	t.Helper()
	params, err := hkdfprf.NewParameters(len(keyBytes), hkdfprf.SHA256, salt)
	if err != nil {
		t.Fatalf("hkdfprf.NewParameters() failed: %v", err)
	}
	key, err := hkdfprf.NewKey(secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}), params)
	if err != nil {
		t.Fatalf("hkdfprf.NewKey() failed: %v", err)
	}
	return key
}

// TODO(b/425280769): Use all relevant test vectors from
// https://github.com/C2SP/wycheproof/blob/main/testvectors/hkdf_sha256_test.json.
func TestDeriveKey_TestVectors(t *testing.T) {
	aes128GCMParamsTink := mustCreateAESGCMParams(t, aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	aes256GCMParamsTink := mustCreateAESGCMParams(t, aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantTink,
	})
	aes256GCMParamsNoPrefix := mustCreateAESGCMParams(t, aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	hmacSHA256ParamsTink := mustCreateHMACParameters(t, hmac.ParametersOpts{
		KeySizeInBytes: 16,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantTink,
	})
	hmacSHA256ParamsNoPrefix := mustCreateHMACParameters(t, hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        hmac.VariantNoPrefix,
	})
	hmacSHA512ParamsNoPrefix := mustCreateHMACParameters(t, hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 32,
		HashType:       hmac.SHA512,
		Variant:        hmac.VariantNoPrefix,
	})

	for _, tv := range []struct {
		name           string
		derivationSalt []byte
		wantKeyValue   []byte
		salt           []byte
		keyBytes       []byte
	}{
		{
			// https://github.com/C2SP/wycheproof/blob/4a6c2bf5dc4c0b67c770233ad33961ee653996a0/testvectors/hkdf_sha256_test.json#L57
			name:           "tc3",
			derivationSalt: mustHexDecode(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			wantKeyValue:   mustHexDecode(t, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
			salt:           mustHexDecode(t, "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
			keyBytes:       mustHexDecode(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
		},
		{
			// https://github.com/C2SP/wycheproof/blob/4a6c2bf5dc4c0b67c770233ad33961ee653996a0/testvectors/hkdf_sha256_test.json#L907
			name:           "tc74",
			derivationSalt: mustHexDecode(t, "9eaddd1e7edb6b84c96fb5ac7e0d673a8f5084f2"),
			wantKeyValue:   mustHexDecode(t, "c746740b67f49da7bb6f5d5e6cb5e23509bece3637f33c45abd96fd8b1da48772baf655f24049af16451"),
			salt:           []byte{},
			keyBytes:       mustHexDecode(t, "6948521434707e96fa943e44988d1ad409ec57e6594867e8193e9d727238916d"),
		},
		{
			// https://github.com/C2SP/wycheproof/blob/4a6c2bf5dc4c0b67c770233ad33961ee653996a0/testvectors/hkdf_sha256_test.json#L955
			name:           "tc78",
			derivationSalt: []byte{},
			wantKeyValue:   mustHexDecode(t, "547e55f20ca5d7eb38596f6b60f9bcada416cb9c987439ad3c772b27b98cd39d954f7ca5d60c05164b7680ea25b101310671a427162e39baf08f8efa5d0569c3"),
			salt:           mustHexDecode(t, "962d86949506450eaca929286ce5d9e7"),
			keyBytes:       mustHexDecode(t, "917ad396520e454a571ac39a9f6bc845a8920954fba1ac400cb2988cd8847ba0"),
		},
	} {
		hkdfPRFKey := mustCreateHKDFPRFKey(t, tv.keyBytes, tv.salt)
		for _, tc := range []struct {
			name    string
			k       *prfbasedkeyderivation.Key
			wantKey key.Key
		}{
			{
				name:    "AES128_GCM_TINK",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, aes128GCMParamsTink, 1234),
				wantKey: mustCreateAESGCMKey(t, tv.wantKeyValue[:16], aes128GCMParamsTink, 1234),
			},
			{
				name:    "AES256_GCM_TINK",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, aes256GCMParamsTink, 3456),
				wantKey: mustCreateAESGCMKey(t, tv.wantKeyValue[:32], aes256GCMParamsTink, 3456),
			},
			{
				name:    "AES256_GCM_NO_PREFIX",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, aes256GCMParamsNoPrefix, 0),
				wantKey: mustCreateAESGCMKey(t, tv.wantKeyValue[:32], aes256GCMParamsNoPrefix, 0),
			},
			{
				name:    "HMAC_SHA256_TINK",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, hmacSHA256ParamsTink, 3322),
				wantKey: mustCreateHMACKey(t, tv.wantKeyValue[:16], hmacSHA256ParamsTink, 3322),
			},
			{
				name:    "HMAC_SHA256_NO_PREFIX",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, hmacSHA256ParamsNoPrefix, 0),
				wantKey: mustCreateHMACKey(t, tv.wantKeyValue[:32], hmacSHA256ParamsNoPrefix, 0),
			},
			{
				name:    "HMAC_SHA512_NO_PREFIX",
				k:       mustCreateKey(t, hkdfPRFKey.Parameters(), hkdfPRFKey, hmacSHA512ParamsNoPrefix, 0),
				wantKey: mustCreateHMACKey(t, tv.wantKeyValue[:32], hmacSHA512ParamsNoPrefix, 0),
			},
		} {
			t.Run(tv.name+"_"+tc.name, func(t *testing.T) {
				d, err := prfbasedkeyderivation.NewKeyDeriver(tc.k, internalapi.Token{})
				if err != nil {
					t.Fatalf("prfbasedkeyderivation.NewKeyDeriver() err = %v, want nil", err)
				}
				derivedKey, err := d.DeriveKey(tv.derivationSalt)
				if err != nil {
					t.Fatalf("DeriveKey() err = %v, want nil", err)
				}
				if !tc.wantKey.Equal(derivedKey) {
					t.Errorf("derived key = %v, want %v", derivedKey, tc.wantKey)
				}
			})
		}
	}
}
