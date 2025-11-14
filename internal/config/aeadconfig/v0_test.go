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

package aeadconfig_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcmsiv"
	"github.com/tink-crypto/tink-go/v2/aead/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/aeadconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	ctrpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_go_proto"
	achpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	aesgcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	aesgcmsivpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_siv_go_proto"
	cc30p1305pb "github.com/tink-crypto/tink-go/v2/proto/chacha20_poly1305_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	xcc30p1305pb "github.com/tink-crypto/tink-go/v2/proto/xchacha20_poly1305_go_proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err=%v, want nil", m, err)
	}
	return b
}

func TestConfigV0AEAD(t *testing.T) {
	configV0 := aeadconfig.V0()

	// AES-CTR-HMAC.
	aesCTRHMACParams, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  32,
		HMACKeySizeInBytes: 32,
		TagSizeInBytes:     32,
		IVSizeInBytes:      16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err=%v, want nil", err)
	}
	aesCTRHMACKey, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
		AESKeyBytes:   secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}),
		HMACKeyBytes:  secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}),
		IDRequirement: 0,
		Parameters:    aesCTRHMACParams,
	})
	if err != nil {
		t.Fatalf(" aesctrhmac.NewKey() err=%v, want nil", err)
	}

	// AES-GCM.
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		IVSizeInBytes:  12,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err=%v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aesgcm.NewKey() err=%v, want nil", err)
	}

	// AES-GCM-SIV.
	aesGCMSIVParams, err := aesgcmsiv.NewParameters(32, aesgcmsiv.VariantNoPrefix)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters() err=%v, want nil", err)
	}
	aesGCMSIVKey, err := aesgcmsiv.NewKey(secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}), 0, aesGCMSIVParams)
	if err != nil {
		t.Fatalf(" aesgcmsiv.NewKey() err=%v, want nil", err)
	}

	// CHACHA20-POLY1305.
	chaCha20Poly1305Params, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters() err=%v, want nil", err)
	}
	chaCha20Poly1305Key, err := chacha20poly1305.NewKey(secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}), 0, chaCha20Poly1305Params)
	if err != nil {
		t.Fatalf(" chacha20poly1305.NewKey() err=%v, want nil", err)
	}

	// X-CHACHA20-POLY1305.
	xchaCha20Poly1305Params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantNoPrefix)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err=%v, want nil", err)
	}
	xchaCha20Poly1305Key, err := xchacha20poly1305.NewKey(secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}), 0, xchaCha20Poly1305Params)
	if err != nil {
		t.Fatalf(" xchacha20poly1305.NewKey() err=%v, want nil", err)
	}

	for _, test := range []struct {
		name       string
		key        key.Key
		keyData    *tinkpb.KeyData
		ciphertext string
	}{
		{
			name: "AES-CTR-HMAC",
			key:  aesCTRHMACKey,
			keyData: &tinkpb.KeyData{
				TypeUrl:         testutil.AESCTRHMACTypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value: mustMarshal(t, &achpb.AesCtrHmacAeadKey{
					Version: 0,
					AesCtrKey: &ctrpb.AesCtrKey{
						Version:  0,
						KeyValue: make([]byte, 32),
						Params:   &ctrpb.AesCtrParams{IvSize: 16},
					},
					HmacKey: &hmacpb.HmacKey{
						Version:  0,
						KeyValue: make([]byte, 32),
						Params:   &hmacpb.HmacParams{Hash: commonpb.HashType_SHA256, TagSize: 32},
					},
				}),
			},
			ciphertext: "ad99a2c8aa74afdcac06b6b1ff9bddf156d27b8f08cf6a452b385596bd468ecfd3eee47d2a1054c178c9f0cc0e17fd5ec855f44d2b44935b03fa81e8e4882f059983f7de82c79046b6",
		},
		{
			name: "AES-GCM",
			key:  aesGCMKey,
			keyData: &tinkpb.KeyData{
				TypeUrl:         testutil.AESGCMTypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value: mustMarshal(t, &aesgcmpb.AesGcmKey{
					Version:  testutil.AESGCMKeyVersion,
					KeyValue: make([]byte, 32),
				}),
			},
			ciphertext: "78e5a9c49bcd68f212ab26ca1f08d173a2e842802488b805f73b4b902a2b9b51706d5cdefffcbf8dcc4506fa8706d9a3c71018dc11",
		},
		{
			name: "CHACHA20-POLY1305",
			key:  chaCha20Poly1305Key,
			keyData: &tinkpb.KeyData{
				TypeUrl:         testutil.ChaCha20Poly1305TypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value: mustMarshal(t, &cc30p1305pb.ChaCha20Poly1305Key{
					Version:  testutil.ChaCha20Poly1305KeyVersion,
					KeyValue: make([]byte, 32),
				}),
			},
			ciphertext: "19af0737e87ced9c95d9e05afd2136ef084ec7635238e59e193bde2f9d5e44812aedd917b3ebcde0339cc3e3cd3b91f224768e9299",
		},
		{
			name: "X-CHACHA20-POLY1305",
			key:  xchaCha20Poly1305Key,
			keyData: &tinkpb.KeyData{
				TypeUrl:         testutil.ChaCha20Poly1305TypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value: mustMarshal(t, &xcc30p1305pb.XChaCha20Poly1305Key{
					Version:  testutil.XChaCha20Poly1305KeyVersion,
					KeyValue: make([]byte, 32),
				}),
			},
			ciphertext: "3a14e26b23a042cd0976ff846c27762edabf9c0bca6901f05891bdfd79dd98fb352c6ab2167883262a2b7a8508e0ebaf4ea08a02215b44518171b317190674a935",
		},
		{
			name: "AES-GCM-SIV",
			key:  aesGCMSIVKey,
			keyData: &tinkpb.KeyData{
				TypeUrl:         testutil.ChaCha20Poly1305TypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value: mustMarshal(t, &aesgcmsivpb.AesGcmSivKey{
					Version:  testutil.AESGCMSIVKeyVersion,
					KeyValue: make([]byte, 32),
				}),
			},
			ciphertext: "e3e3352092e8b0309f38192ec526c391fc65c963d92831f25699882c5203e2b7a4ce5d920ef736fc74120447325806a47dfc08f254",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			aead, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err=%v, want nil", err)
			}
			a, ok := aead.(tink.AEAD)
			if !ok {
				t.Fatalf("aead was of type %v, want tink.AEAD", reflect.TypeOf(aead))
			}

			plaintext := []byte("this is a test ciphertext")
			aad := []byte("this is an aad")
			ct, err := hex.DecodeString(test.ciphertext)
			if err != nil {
				t.Fatalf("hex.Decode(ciphertext) err=%v, want nil", err)
			}
			pt, err := a.Decrypt(ct, aad)
			if err != nil {
				t.Fatalf("aead.Decrypt known ciphertext err=%v, want nil", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("Decrypted plaintext=%q, want %q", pt, plaintext)
			}
		})
	}
}
