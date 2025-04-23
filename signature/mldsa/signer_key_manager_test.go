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

package mldsa_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/tink"
	mldsapb "github.com/tink-crypto/tink-go/v2/proto/ml_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerKeyManagerGetPrimitiveBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
	}{
		{
			name:     "MLDSA65",
			instance: tinkmldsa.MLDSA65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey")
			if err != nil {
				t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey", err)
			}

			params, err := tinkmldsa.NewParameters(tc.instance, tinkmldsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters(%v) err = %v, want nil", tinkmldsa.VariantNoPrefix, err)
			}
			_, privateKeyBytes := getTestKeyPair(t, tc.instance)
			privateKey, err := tinkmldsa.NewPrivateKey(secretdata.NewBytesFromData(privateKeyBytes, insecuresecretdataaccess.Token{}), 0, params)
			if err != nil {
				t.Fatalf("tinkmldsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, 0, params, err)
			}

			keySerialization, err := protoserialization.SerializeKey(privateKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", privateKey, err)
			}
			p, err := km.Primitive(keySerialization.KeyData().GetValue())
			if err != nil {
				t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) err = %v, want nil", err)
			}
			s, ok := p.(tink.Signer)
			if !ok {
				t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) = %T, want %T", p, (tink.Signer)(nil))
			}

			pubKey, err := privateKey.PublicKey()
			if err != nil {
				t.Fatalf("privateKey.PublicKey() err = %v, want nil", err)
			}
			actualPubKey, ok := pubKey.(*tinkmldsa.PublicKey)
			if !ok {
				t.Fatalf("not a *tinkmldsa.PublicKey: %v", pubKey)
			}
			v, err := tinkmldsa.NewVerifier(actualPubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", actualPubKey, err)
			}

			message := []byte("message")
			got, err := s.Sign(message)
			if err != nil {
				t.Fatalf("signer.Sign(%x) err = %v, want nil", message, err)
			}
			if err := v.Verify(got, message); err != nil {
				t.Errorf("v.Verify(%x, %x) err = %v, want nil", got, message, err)
			}
		})
	}
}

func TestSignerKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey")
	if err != nil {
		t.Errorf("cannot obtain MLDSASigner key manager: %s", err)
	}

	// invalid version
	for _, tc := range []struct {
		name     string
		instance mldsapb.MlDsaInstance
	}{
		{
			name:     "MLDSA65",
			instance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := newMLDSAPrivateKey(tc.instance)
			key.Version = 1
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("expect an error when version is invalid")
			}
			// nil input
			if _, err := km.Primitive(nil); err == nil {
				t.Errorf("expect an error when input is nil")
			}
			if _, err := km.Primitive([]byte{}); err == nil {
				t.Errorf("expect an error when input is empty slice")
			}
		})
	}
}

func TestSignerKeyManagerNewKeyDataBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance mldsapb.MlDsaInstance
	}{
		{
			name:     "MLDSA65",
			instance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain MLDSASigner key manager: %s", err)
			}
			keyFormat := &mldsapb.MlDsaKeyFormat{
				Version: 0,
				Params: &mldsapb.MlDsaParams{
					MlDsaInstance: tc.instance,
				},
			}
			serializedFormat, err := proto.Marshal(keyFormat)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			tmp, err := km.NewKeyData(serializedFormat)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			var key mldsapb.MlDsaPrivateKey
			if err := proto.Unmarshal(tmp.Value, &key); err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if err := validateMLDSAPrivateKey(tc.instance, &key); err != nil {
				t.Errorf("invalid private key in test case: %s", err)
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyDataBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance mldsapb.MlDsaInstance
	}{
		{
			name:     "MLDSA65",
			instance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain MLDSASigner key manager: %s", err)
			}
			pkm, ok := km.(registry.PrivateKeyManager)
			if !ok {
				t.Errorf("cannot obtain private key manager")
			}

			key := newMLDSAPrivateKey(tc.instance)
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}

			pubKeyData, err := pkm.PublicKeyData(serializedKey)
			if err != nil {
				t.Errorf("unexpect error in test case: %s ", err)
			}
			if pubKeyData.TypeUrl != "type.googleapis.com/google.crypto.tink.MlDsaPublicKey" {
				t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
			}
			if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
				t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
			}
			pubKey := new(mldsapb.MlDsaPublicKey)
			if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
				t.Errorf("invalid public key: %s", err)
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyDataWithInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance mldsapb.MlDsaInstance
	}{
		{
			name:     "MLDSA65",
			instance: mldsapb.MlDsaInstance_ML_DSA_65,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.MlDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain MLDSASigner key manager: %s", err)
			}
			pkm, ok := km.(registry.PrivateKeyManager)
			if !ok {
				t.Errorf("cannot obtain private key manager")
			}
			// modified key
			key := newMLDSAPrivateKey(tc.instance)
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}
			serializedKey[0] = 0
			if _, err := pkm.PublicKeyData(serializedKey); err == nil {
				t.Errorf("expect an error when input is a modified serialized key")
			}
			// invalid with a single byte
			if _, err := pkm.PublicKeyData([]byte{42}); err == nil {
				t.Errorf("expect an error when input is an empty slice")
			}
		})
	}
}

func newMLDSAPrivateKey(instance mldsapb.MlDsaInstance) *mldsapb.MlDsaPrivateKey {
	switch instance {
	case mldsapb.MlDsaInstance_ML_DSA_65:
		public, private := mldsa.MLDSA65.KeyGen()
		publicProto := &mldsapb.MlDsaPublicKey{
			Params: &mldsapb.MlDsaParams{
				MlDsaInstance: mldsapb.MlDsaInstance_ML_DSA_65,
			},
			Version:  0,
			KeyValue: public.Encode(),
		}
		seed := private.Seed()
		return &mldsapb.MlDsaPrivateKey{
			Version:   0,
			PublicKey: publicProto,
			KeyValue:  seed[:],
		}
	default:
		panic(fmt.Sprintf("Unsupported MLDSA instance: %v", instance))
	}
}

func validateMLDSAPrivateKey(instance mldsapb.MlDsaInstance, key *mldsapb.MlDsaPrivateKey) error {
	if key.Version != 0 {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			0, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != 0 {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			0, key.Version)
	}

	var pub *mldsa.PublicKey
	var seedBytes [mldsa.SecretKeySeedSize]byte
	copy(seedBytes[:], key.KeyValue)

	switch instance {
	case mldsapb.MlDsaInstance_ML_DSA_65:
		pub, _ = mldsa.MLDSA65.KeyGenFromSeed(seedBytes)
	default:
		return fmt.Errorf("unsupported instance: %v", instance)
	}

	pubEncoded := pub.Encode()
	if !bytes.Equal(pubEncoded, publicKey.KeyValue) {
		return fmt.Errorf("incorrect public key's key value: expect %x, got %x", pubEncoded, publicKey.KeyValue)
	}

	return nil
}
