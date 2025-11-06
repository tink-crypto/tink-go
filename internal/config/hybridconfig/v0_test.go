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

package hybridconfig_test

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/hybrid/ecies"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/internal/config/hybridconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestConfigV0EncryptDecryptFailsIfKeyNotHybrid(t *testing.T) {
	configV0 := hybridconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aescmac.NewParameters() err=%v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), testonlyinsecuresecretdataaccess.Token()), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aescmac.NewKey() err=%v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKeyData() err=nil, want error")
	}
}

func TestConfigV0EncryptDecrypt(t *testing.T) {
	configV0 := hybridconfig.V0()

	hpkeParams, err := hpke.NewParameters(hpke.ParametersOpts{
		KEMID:   hpke.DHKEM_P256_HKDF_SHA256,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES128GCM,
		Variant: hpke.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("hpke.NewParameters() err=%v, want nil", err)
	}
	hpkePrivKey, err := keygenregistry.CreateKey(hpkeParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err=%v, want nil", err)
	}

	eciesDemParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 16,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err=%v, want nil", err)
	}
	eciesParams, err := ecies.NewParameters(ecies.ParametersOpts{
		CurveType:            ecies.NISTP256,
		HashType:             ecies.SHA256,
		NISTCurvePointFormat: ecies.UncompressedPointFormat,
		DEMParameters:        eciesDemParams,
		Variant:              ecies.VariantNoPrefix,
	})
	if err != nil {
		t.Fatalf("ecies.NewParameters() err=%v, want nil", err)
	}
	eciesPrivKey, err := keygenregistry.CreateKey(eciesParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err=%v, want nil", err)
	}

	for _, test := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "HPKE",
			key:  hpkePrivKey,
		},
		{
			name: "ECIES",
			key:  eciesPrivKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ps, err := protoserialization.SerializeKey(test.key)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
			}
			if _, err := configV0.PrimitiveFromKeyData(ps.KeyData(), internalapi.Token{}); err == nil {
				t.Fatalf("configV0.PrimitiveFromKeyData() err = nil, want error")
			}

			primitive, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err=%v, want nil", err)
			}
			decrypter, ok := primitive.(tink.HybridDecrypt)
			if !ok {
				t.Fatalf("primitive is of type %v, want tink.HybridDecrypt", reflect.TypeOf(primitive))
			}

			privKey := test.key.(interface {
				PublicKey() (key.Key, error)
			})
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err=%v, want nil", err)
			}
			primitive, err = configV0.PrimitiveFromKey(pubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err=%v, want nil", err)
			}
			encrypter, ok := primitive.(tink.HybridEncrypt)
			if !ok {
				t.Fatalf("primitive is of type %v, want tink.HybridEncrypt", reflect.TypeOf(primitive))
			}

			plaintext := []byte("plaintext")
			contextInfo := []byte("context info")
			ciphertext, err := encrypter.Encrypt(plaintext, contextInfo)
			if err != nil {
				t.Fatalf("encrypter.Encrypt() err=%v, want nil", err)
			}
			gotPlaintext, err := decrypter.Decrypt(ciphertext, contextInfo)
			if err != nil {
				t.Fatalf("decrypter.Decrypt() err=%v, want nil", err)
			}
			if string(gotPlaintext) != string(plaintext) {
				t.Errorf("decrypter.Decrypt() = %q, want %q", gotPlaintext, plaintext)
			}
		})
	}
}
