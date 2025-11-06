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

package slhdsa_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/tink"
	slhdsapb "github.com/tink-crypto/tink-go/v2/proto/slh_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestSignerKeyManagerGetPrimitiveBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey")
			if err != nil {
				t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey", err)
			}

			params, err := tinkslhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tinkslhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewParameters(%v) err = %v, want nil", tinkslhdsa.VariantNoPrefix, err)
			}
			keyPair := generateTestKeyPair(t, tc.hashType, tc.keySize, tc.sigType)
			privateKey, err := tinkslhdsa.NewPrivateKey(secretdata.NewBytesFromData(keyPair.privKey, insecuresecretdataaccess.Token{}), 0, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPrivateKey(%v, %v, %v) err = %v, want nil", keyPair.privKey, 0, params, err)
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
			actualPubKey, ok := pubKey.(*tinkslhdsa.PublicKey)
			if !ok {
				t.Fatalf("not a *tinkslhdsa.PublicKey: %v", pubKey)
			}
			v, err := tinkslhdsa.NewVerifier(actualPubKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkslhdsa.NewVerifier(%v, internalapi.Token{}) err = %v, want nil", actualPubKey, err)
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
	km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey")
	if err != nil {
		t.Errorf("cannot obtain SLHDSASigner key manager: %s", err)
	}

	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// invalid version
			key := newSLHDSAPrivateKey(tc.hashType, tc.keySize, tc.sigType)
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
		hashType slhdsapb.SlhDsaHashType
		keySize  int32
		sigType  slhdsapb.SlhDsaSignatureType
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: slhdsapb.SlhDsaHashType_SHA2,
			keySize:  64,
			sigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: slhdsapb.SlhDsaHashType_SHAKE,
			keySize:  128,
			sigType:  slhdsapb.SlhDsaSignatureType_FAST_SIGNING,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain SLHDSASigner key manager: %s", err)
			}
			keyFormat := &slhdsapb.SlhDsaKeyFormat{
				Version: 0,
				Params: &slhdsapb.SlhDsaParams{
					KeySize:  tc.keySize,
					HashType: tc.hashType,
					SigType:  tc.sigType,
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
			var key slhdsapb.SlhDsaPrivateKey
			if err := proto.Unmarshal(tmp.Value, &key); err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if err := validateSLHDSAPrivateKey(tc.hashType, tc.keySize, tc.sigType, &key); err != nil {
				t.Errorf("invalid private key in test case: %s", err)
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyDataBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain SLHDSASigner key manager: %s", err)
			}
			pkm, ok := km.(registry.PrivateKeyManager)
			if !ok {
				t.Errorf("cannot obtain private key manager")
			}

			key := newSLHDSAPrivateKey(tc.hashType, tc.keySize, tc.sigType)
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %v, want nil", err)
			}

			pubKeyData, err := pkm.PublicKeyData(serializedKey)
			if err != nil {
				t.Errorf("unexpect error in test case: %s ", err)
			}
			if pubKeyData.TypeUrl != "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey" {
				t.Errorf("incorrect type url: %s", pubKeyData.TypeUrl)
			}
			if pubKeyData.KeyMaterialType != tinkpb.KeyData_ASYMMETRIC_PUBLIC {
				t.Errorf("incorrect key material type: %d", pubKeyData.KeyMaterialType)
			}
			pubKey := new(slhdsapb.SlhDsaPublicKey)
			if err = proto.Unmarshal(pubKeyData.Value, pubKey); err != nil {
				t.Errorf("invalid public key: %s", err)
			}
		})
	}
}

func TestSignerKeyManagerPublicKeyDataWithInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
		},
		{
			name:     "SLH-DSA-SHAKE-256f",
			hashType: tinkslhdsa.SHAKE,
			keySize:  128,
			sigType:  tinkslhdsa.FastSigning,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey")
			if err != nil {
				t.Errorf("cannot obtain SLHDSASigner key manager: %s", err)
			}
			pkm, ok := km.(registry.PrivateKeyManager)
			if !ok {
				t.Errorf("cannot obtain private key manager")
			}
			// modified key
			key := newSLHDSAPrivateKey(tc.hashType, tc.keySize, tc.sigType)
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

func newSLHDSAPrivateKey(hashType tinkslhdsa.HashType, keySize int, sigType tinkslhdsa.SignatureType) *slhdsapb.SlhDsaPrivateKey {
	if hashType == tinkslhdsa.SHA2 && keySize == 64 && sigType == tinkslhdsa.SmallSignature {
		private, public := slhdsa.SLH_DSA_SHA2_128s.KeyGen()
		publicProto := &slhdsapb.SlhDsaPublicKey{
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
			Version:  0,
			KeyValue: public.Encode(),
		}
		return &slhdsapb.SlhDsaPrivateKey{
			Version:   0,
			PublicKey: publicProto,
			KeyValue:  private.Encode(),
		}
	}
	if hashType == tinkslhdsa.SHAKE && keySize == 128 && sigType == tinkslhdsa.FastSigning {
		private, public := slhdsa.SLH_DSA_SHAKE_256f.KeyGen()
		publicProto := &slhdsapb.SlhDsaPublicKey{
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  128,
				HashType: slhdsapb.SlhDsaHashType_SHAKE,
				SigType:  slhdsapb.SlhDsaSignatureType_FAST_SIGNING,
			},
			Version:  0,
			KeyValue: public.Encode(),
		}
		return &slhdsapb.SlhDsaPrivateKey{
			Version:   0,
			PublicKey: publicProto,
			KeyValue:  private.Encode(),
		}
	}
	panic(fmt.Sprintf("Unsupported SLH-DSA parameters: %v, %v, %v", hashType, keySize, sigType))
}

func validateSLHDSAPrivateKey(hashType slhdsapb.SlhDsaHashType, keySize int32, sigType slhdsapb.SlhDsaSignatureType, key *slhdsapb.SlhDsaPrivateKey) error {
	if key.Version != 0 {
		return fmt.Errorf("incorrect private key's version: expect %d, got %d",
			0, key.Version)
	}
	publicKey := key.PublicKey
	if publicKey.Version != 0 {
		return fmt.Errorf("incorrect public key's version: expect %d, got %d",
			0, key.Version)
	}

	var secretKey *slhdsa.SecretKey
	if hashType == slhdsapb.SlhDsaHashType_SHA2 && keySize == 64 && sigType == slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE {
		sk, err := slhdsa.SLH_DSA_SHA2_128s.DecodeSecretKey(key.KeyValue)
		if err != nil {
			return fmt.Errorf("DecodeSecretKey() failed: %w", err)
		}
		secretKey = sk
	} else if hashType == slhdsapb.SlhDsaHashType_SHAKE && keySize == 128 && sigType == slhdsapb.SlhDsaSignatureType_FAST_SIGNING {
		sk, err := slhdsa.SLH_DSA_SHAKE_256f.DecodeSecretKey(key.KeyValue)
		if err != nil {
			return fmt.Errorf("DecodeSecretKey() failed: %w", err)
		}
		secretKey = sk
	} else {
		return fmt.Errorf("unsupported SLH-DSA parameters: %v, %v, %v", hashType, keySize, sigType)
	}

	pubEncoded := secretKey.PublicKey().Encode()
	if !bytes.Equal(pubEncoded, publicKey.KeyValue) {
		return fmt.Errorf("incorrect public key's key value: expect %x, got %x", pubEncoded, publicKey.KeyValue)
	}

	return nil
}
