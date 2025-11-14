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

package signatureconfig_test

import (
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/signatureconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keygenregistry"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestConfigV0MACFailsIfKeyNotSignerOrVerifier(t *testing.T) {
	configV0 := signatureconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aescmac.NewParameters() err=%v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aescmac.NewKey() err=%v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKey() err=nil, want error")
	}
}

func TestConfigV0Signer(t *testing.T) {
	configV0 := signatureconfig.V0()

	// ECDSA
	ecdsaParams, err := ecdsa.NewParameters(ecdsa.NistP256, ecdsa.SHA256, ecdsa.DER, ecdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ecdsa.NewParameters() err = %v, want nil", err)
	}
	ecdsaPrivKey, err := keygenregistry.CreateKey(ecdsaParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	// Ed25519
	ed25519Params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters() err = %v, want nil", err)
	}
	ed25519PrivKey, err := keygenregistry.CreateKey(&ed25519Params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	// ML-DSA
	mldsaParams, err := mldsa.NewParameters(mldsa.MLDSA65, mldsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("mldsa.NewParameters() err = %v, want nil", err)
	}
	mldsaPrivKey, err := keygenregistry.CreateKey(mldsaParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	// RSA-SSA-PKCS1
	rsapkcs1Params, err := rsassapkcs1.NewParameters(2048, rsassapkcs1.SHA256, 65537, rsassapkcs1.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	rsapkcs1PrivKey, err := keygenregistry.CreateKey(rsapkcs1Params, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	// RSA-SSA-PSS
	rsapssParams, err := rsassapss.NewParameters(rsassapss.ParametersValues{
		ModulusSizeBits: 2048,
		SigHashType:     rsassapss.SHA256,
		MGF1HashType:    rsassapss.SHA256,
		PublicExponent:  65537,
		SaltLengthBytes: 32,
	}, rsassapss.VariantNoPrefix)
	if err != nil {
		t.Fatalf("rsassapss.NewParameters() err = %v, want nil", err)
	}
	rsapssPrivKey, err := keygenregistry.CreateKey(rsapssParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	// SLH-DSA
	slhdsaParams, err := slhdsa.NewParameters(slhdsa.SHA2, 64, slhdsa.SmallSignature, slhdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("slhdsa.NewParameters() err = %v, want nil", err)
	}
	slhdsaPrivKey, err := keygenregistry.CreateKey(slhdsaParams, 0)
	if err != nil {
		t.Fatalf("keygenregistry.CreateKey() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name string
		key  key.Key
	}{
		{
			name: "ECDSA",
			key:  ecdsaPrivKey,
		},
		{
			name: "Ed25519",
			key:  ed25519PrivKey,
		},
		{
			name: "ML-DSA",
			key:  mldsaPrivKey,
		},
		{
			name: "RSA-SSA-PKCS1",
			key:  rsapkcs1PrivKey,
		},
		{
			name: "RSA-SSA-PSS",
			key:  rsapssPrivKey,
		},
		{
			name: "SLH-DSA",
			key:  slhdsaPrivKey,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			primitive, err := configV0.PrimitiveFromKey(test.key, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			signer, ok := primitive.(tink.Signer)
			if !ok {
				t.Fatalf("primitive is of type %v, want tink.Signer", reflect.TypeOf(primitive))
			}
			data := []byte("data")
			sig, err := signer.Sign(data)
			if err != nil {
				t.Fatalf("signer.Sign() err = %v, want nil", err)
			}
			// Get verifier from config and verify.
			privKey := test.key.(interface {
				PublicKey() (key.Key, error)
			})
			pubKey, err := privKey.PublicKey()
			if err != nil {
				t.Fatalf("privKey.PublicKey() err = %v, want nil", err)
			}
			primitive, err = configV0.PrimitiveFromKey(pubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			verifier, ok := primitive.(tink.Verifier)
			if !ok {
				t.Fatalf("primitive is of type %v, want tink.Verifier", reflect.TypeOf(primitive))
			}
			if err := verifier.Verify(sig, data); err != nil {
				t.Errorf("verifier.Verify() err = %v, want nil", err)
			}
		})
	}
}
