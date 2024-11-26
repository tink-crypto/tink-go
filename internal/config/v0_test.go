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

package config_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
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

func TestConfigV0AEADKeyManagers(t *testing.T) {
	configV0 := config.V0()

	for _, test := range []struct {
		typeURL    string
		key        proto.Message
		ciphertext string
	}{
		{
			testutil.AESCTRHMACAEADTypeURL,
			&achpb.AesCtrHmacAeadKey{
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
			},
			"ad99a2c8aa74afdcac06b6b1ff9bddf156d27b8f08cf6a452b385596bd468ecfd3eee47d2a1054c178c9f0cc0e17fd5ec855f44d2b44935b03fa81e8e4882f059983f7de82c79046b6",
		},
		{
			testutil.AESGCMTypeURL,
			&aesgcmpb.AesGcmKey{
				Version:  testutil.AESGCMKeyVersion,
				KeyValue: make([]byte, 32),
			},
			"78e5a9c49bcd68f212ab26ca1f08d173a2e842802488b805f73b4b902a2b9b51706d5cdefffcbf8dcc4506fa8706d9a3c71018dc11",
		},
		{
			testutil.ChaCha20Poly1305TypeURL,
			&cc30p1305pb.ChaCha20Poly1305Key{
				Version:  testutil.ChaCha20Poly1305KeyVersion,
				KeyValue: make([]byte, 32),
			},
			"19af0737e87ced9c95d9e05afd2136ef084ec7635238e59e193bde2f9d5e44812aedd917b3ebcde0339cc3e3cd3b91f224768e9299",
		},
		{
			testutil.XChaCha20Poly1305TypeURL,
			&xcc30p1305pb.XChaCha20Poly1305Key{
				Version:  testutil.XChaCha20Poly1305KeyVersion,
				KeyValue: make([]byte, 32),
			},
			"3a14e26b23a042cd0976ff846c27762edabf9c0bca6901f05891bdfd79dd98fb352c6ab2167883262a2b7a8508e0ebaf4ea08a02215b44518171b317190674a935",
		},
		{
			testutil.AESGCMSIVTypeURL,
			&aesgcmsivpb.AesGcmSivKey{
				Version:  testutil.AESGCMSIVKeyVersion,
				KeyValue: make([]byte, 32),
			},
			"e3e3352092e8b0309f38192ec526c391fc65c963d92831f25699882c5203e2b7a4ce5d920ef736fc74120447325806a47dfc08f254",
		},
	} {
		t.Run(test.typeURL, func(t *testing.T) {
			serializedKey, err := proto.Marshal(test.key)
			if err != nil {
				t.Fatalf("proto.Marshal(%v): err=%v, want nil", test.key, err)
			}
			keyData := &tinkpb.KeyData{
				TypeUrl:         test.typeURL,
				Value:           serializedKey,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			}
			aead, err := configV0.PrimitiveFromKeyData(keyData, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKeyData(%s) err=%v, want nil", test.typeURL, err)
			}
			a, ok := aead.(tink.AEAD)
			if !ok {
				t.Fatalf("aead was of type %v, want tink.AEAD", reflect.TypeOf(aead))
			}

			plaintext := "this is a test ciphertext"
			aad := []byte("this is an aad")
			ct, err := hex.DecodeString(test.ciphertext)
			if err != nil {
				t.Fatalf("hex.Decode(ciphertext) err=%v, want nil", err)
			}
			pt, err := a.Decrypt(ct, aad)
			if err != nil {
				t.Fatalf("aead.Decrypt known ciphertext err=%v, want nil", err)
			}
			if string(pt) != plaintext {
				t.Errorf("Decrypted plaintext=%q, want %q", pt, plaintext)
			}
		})
	}
}
