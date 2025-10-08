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

package slhdsa

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	slhdsapb "github.com/tink-crypto/tink-go/v2/proto/slh_dsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	// Copied from Tink C++ SLH-DSA signature verification test.
	privKeyHex = "d44f6f06a73a07451096ad4bfbd240cb54b779330a65ed34ec0cd372c96fe48bf2b907c6" +
		"b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3"
	pubKeyHex = "f2b907c6b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3"
)

func mustCreateKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParsePublicKeyFails(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := slhdsapb.SlhDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	protoPublicKeyWithWrongPrivateKeyVersion := slhdsapb.SlhDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion + 1,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedProtoPublicKeyWithWrongVersion, err := proto.Marshal(&protoPublicKeyWithWrongPrivateKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKeyWithWrongPrivateKeyVersion) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKeyWithWrongVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := slhdsapb.SlhDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      Variant
	}{
		{
			name: "key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: VariantTink,
		},
		{
			name: "key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant: VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &publicKeyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want nil", tc.keySerialization, err)
			}
			wantParams, err := NewParameters(SHA2, 64, SmallSignature, tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", tc.wantVariant, err)
			}
			idRequirement, _ := tc.keySerialization.IDRequirement()
			wantKey, err := NewPublicKey(protoPublicKey.GetKeyValue(), idRequirement, wantParams)
			if err != nil {
				t.Fatalf("NewPublicKey(%v, %v, %v) err = %v, want nil", protoPublicKey.GetKeyValue(), idRequirement, wantParams, err)
			}
			if !gotKey.Equal(wantKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, wantKey)
			}
			// Test serialization returns back tc.keySerialization.
			s := publicKeySerializer{}
			keySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(gotKey) err = %v, want nil", err)
			}
			if got, want := keySerialization, tc.keySerialization; !got.Equal(want) {
				t.Errorf("s.SerializeKey(gotKey) = %v, want %v", got, want)
			}
		})
	}
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equal(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equal(other key.Key) bool { return true }

func (k *testKey) IDRequirement() (uint32, bool) { return 123, true }

func TestSerializePublicKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		publicKey key.Key
	}{
		{
			name:      "nil public key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			if _, err := s.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

func mustCreatePublicKey(t *testing.T, keyBytes []byte, idRequirement uint32, variant Variant) *PublicKey {
	t.Helper()
	params, err := NewParameters(SHA2, 64, SmallSignature, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", variant, err)
	}
	pubKey, err := NewPublicKey(keyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPublicKey(%v, %v, %v) err = %v, want nil", keyBytes, idRequirement, params, err)
	}
	return pubKey
}

func TestSerializePublicKey(t *testing.T) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	protoPublicKey := slhdsapb.SlhDsaPublicKey{
		KeyValue: keyBytes,
		Version:  publicKeyProtoVersion,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name      string
		publicKey key.Key
		want      *protoserialization.KeySerialization
	}{
		{
			name:      "Public key with TINK output prefix type",
			publicKey: mustCreatePublicKey(t, keyBytes, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:      "Public key with RAW output prefix type",
			publicKey: mustCreatePublicKey(t, keyBytes, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &publicKeySerializer{}
			got, err := s.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
			if !got.Equal(tc.want) {
				t.Errorf("s.SerializeKey(%v) = %v, want %v", tc.publicKey, got, tc.want)
			}
		})
	}
}

func getTestKeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pubKeyHex) err = %v, want nil", err)
	}
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(privKeyHex) err = %v, want nil", err)
	}
	return pubKeyBytes, privKeyBytes
}

func TestParsePrivateKeyFails(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := &slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKey, err)
	}

	protoPublicKeyWithWrongPrivateKeyVersion := &slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: privateKeyProtoVersion + 1,
	}
	serializedProtoPrivateKeyWithWrongPrivateKeyVersion, err := proto.Marshal(protoPublicKeyWithWrongPrivateKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPublicKeyWithWrongPrivateKeyVersion, err)
	}
	protoPrivateKeyWithWrongPublicKeyVersion := &slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion + 1,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: privateKeyProtoVersion,
	}
	serializedProtoPrivateKeyWithWrongPublicKeyVersion, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyVersion, err)
	}

	otherPubKeyBytes := bytes.Clone(pubKeyBytes)
	otherPubKeyBytes[0] = 0x99
	protoPrivateKeyWithWrongPublicKeyBytes := &slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: otherPubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: privateKeyProtoVersion,
	}
	serializedProtoPrivateKeyWithWrongPublicKeyBytes, err := proto.Marshal(protoPrivateKeyWithWrongPublicKeyBytes)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", protoPrivateKeyWithWrongPublicKeyBytes, err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: mustCreateKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, 12345),
		},
		{
			name: "wrong private key material type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong private key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPrivateKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key version",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyVersion,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong public key bytes",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKeyWithWrongPublicKeyBytes,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			if _, err = p.ParseKey(tc.keySerialization); err == nil {
				t.Errorf("p.ParseKey(%v) err = nil, want non-nil", tc.keySerialization)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(&protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey) err = %v, want nil", err)
	}

	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
		wantVariant      Variant
	}{
		{
			name: "key with TINK output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: VariantTink,
		},
		{
			name: "key with RAW output prefix type",
			keySerialization: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
			wantVariant: VariantNoPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &privateKeyParser{}
			gotKey, err := p.ParseKey(tc.keySerialization)
			if err != nil {
				t.Fatalf("p.ParseKey(%v) err = %v, want non-nil", tc.keySerialization, err)
			}
			wantParams, err := NewParameters(SHA2, 64, SmallSignature, tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", tc.wantVariant, err)
			}
			idRequirement, _ := tc.keySerialization.IDRequirement()
			privateKeyBytes := secretdata.NewBytesFromData(protoPrivateKey.GetKeyValue(), insecuresecretdataaccess.Token{})
			wantKey, err := NewPrivateKey(privateKeyBytes, idRequirement, wantParams)
			if err != nil {
				t.Fatalf("NewPrivateKey(%v, %v, %v) err = %v, want nil", privateKeyBytes, idRequirement, wantParams, err)
			}
			if !gotKey.Equal(wantKey) {
				t.Errorf("%v.Equal(%v) = false, want true", gotKey, wantKey)
			}
			// Test serialization returns back tc.keySerialization.
			s := privateKeySerializer{}
			keySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(gotKey) err = %v, want nil", err)
			}
			if got, want := keySerialization, tc.keySerialization; !got.Equal(want) {
				t.Errorf("s.SerializeKey(gotKey) = %v, want %v", got, want)
			}
		})
	}
}

func TestSerializePrivateKeyFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		privateKey key.Key
	}{
		{
			name:       "nil private key",
			privateKey: nil,
		},
		{
			name:       "invlid private key",
			privateKey: &PrivateKey{},
		},
		{
			name:       "incorrect key type",
			privateKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			if _, err := s.SerializeKey(tc.privateKey); err == nil {
				t.Errorf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
		})
	}
}

func mustCreatePrivateKey(t *testing.T, keyBytes secretdata.Bytes, idRequirement uint32, variant Variant) *PrivateKey {
	t.Helper()
	params, err := NewParameters(SHA2, 64, SmallSignature, variant)
	if err != nil {
		t.Fatalf("NewParameters(%v) err = %v, want nil", variant, err)
	}
	pubKey, err := NewPrivateKey(keyBytes, idRequirement, params)
	if err != nil {
		t.Fatalf("NewPrivateKey(%v, %v, %v) err = %v, want nil", keyBytes, idRequirement, params, err)
	}
	return pubKey
}

func TestSerializePrivateKey(t *testing.T) {
	pubKeyBytes, privKeyBytes := getTestKeyPair(t)

	protoPrivateKey := slhdsapb.SlhDsaPrivateKey{
		KeyValue: privKeyBytes,
		PublicKey: &slhdsapb.SlhDsaPublicKey{
			KeyValue: pubKeyBytes,
			Version:  publicKeyProtoVersion,
			Params: &slhdsapb.SlhDsaParams{
				KeySize:  64,
				HashType: slhdsapb.SlhDsaHashType_SHA2,
				SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
			},
		},
		Version: publicKeyProtoVersion,
	}
	serializedProtoPrivateKey, err := proto.Marshal(&protoPrivateKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPrivateKey) err = %v, want nil", err)
	}
	privateKeyBytes := secretdata.NewBytesFromData(privKeyBytes, insecuresecretdataaccess.Token{})
	for _, tc := range []struct {
		name       string
		privateKey *PrivateKey
		want       *protoserialization.KeySerialization
	}{
		{
			name:       "Private key with TINK output prefix type",
			privateKey: mustCreatePrivateKey(t, privateKeyBytes, 12345, VariantTink),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:       "Private key with RAW output prefix type",
			privateKey: mustCreatePrivateKey(t, privateKeyBytes, 0, VariantNoPrefix),
			want: mustCreateKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				Value:           serializedProtoPrivateKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_RAW, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &privateKeySerializer{}
			got, err := s.SerializeKey(tc.privateKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(%v) err = nil, want non-nil", tc.privateKey)
			}
			if !got.Equal(tc.want) {
				t.Errorf("s.SerializeKey(%v) = %v, want %v", tc.privateKey, got, tc.want)
			}
		})
	}
}

func TestSerializeParametersFailsWithWrongParameters(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parameters key.Parameters
	}{
		{
			name:       "empty parameters",
			parameters: &Parameters{},
		},
		{
			name:       "nil",
			parameters: nil,
		},
		{
			name:       "wrong type",
			parameters: &testParams{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializer := &parametersSerializer{}
			if _, err := serializer.Serialize(tc.parameters); err == nil {
				t.Errorf("serializer.Serialize(%v) err = nil, want error", tc.parameters)
			}
		})
	}
}

func TestSerializeParameters(t *testing.T) {
	format := &slhdsapb.SlhDsaKeyFormat{
		Version: 0,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(format) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name       string
		parameters key.Parameters
		want       *tinkpb.KeyTemplate
	}{
		{
			name: "parameters with TINK variant",
			parameters: &Parameters{
				paramSet: parameterSet{
					hashType: SHA2,
					keySize:  64,
					sigType:  SmallSignature,
				},
				variant: VariantTink,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat,
			},
		},
		{
			name: "parameters with NO_PREFIX variant",
			parameters: &Parameters{
				paramSet: parameterSet{
					hashType: SHA2,
					keySize:  64,
					sigType:  SmallSignature,
				},
				variant: VariantNoPrefix,
			},
			want: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeParameters(tc.parameters)
			if err != nil {
				t.Fatalf("protoserialization.SerializeParameters(%v) err = %v, want nil", tc.parameters, err)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("protoserialization.SerializeParameters(%v) returned unexpected diff (-want +got):\n%s", tc.parameters, diff)
			}
		})
	}
}

func TestParseParameters(t *testing.T) {
	format := &slhdsapb.SlhDsaKeyFormat{
		Version: 0,
		Params: &slhdsapb.SlhDsaParams{
			KeySize:  64,
			HashType: slhdsapb.SlhDsaHashType_SHA2,
			SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
		},
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(format) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name     string
		want     key.Parameters
		template *tinkpb.KeyTemplate
	}{
		{
			name: "parameters with TINK variant",
			want: &Parameters{
				paramSet: parameterSet{
					hashType: SHA2,
					keySize:  64,
					sigType:  SmallSignature,
				},
				variant: VariantTink,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            serializedFormat,
			},
		},
		{
			name: "parameters with NO_PREFIX variant",
			want: &Parameters{
				paramSet: parameterSet{
					hashType: SHA2,
					keySize:  64,
					sigType:  SmallSignature,
				},
				variant: VariantNoPrefix,
			},
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				Value:            serializedFormat,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.ParseParameters(tc.template)
			if err != nil {
				t.Fatalf("protoserialization.ParseParameters(%v) err = %v, want nil", tc.template, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("protoserialization.ParseParameters(%v) returned unexpected diff (-want +got):\n%s", tc.template, diff)
			}
		})
	}
}

func mustMarshal(t *testing.T, format proto.Message) []byte {
	t.Helper()
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(format) err = %v, want nil", err)
	}
	return serializedFormat
}

func TestParseParametersFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name: "invalid output prefix type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_UNKNOWN_PREFIX,
				Value: mustMarshal(t, &slhdsapb.SlhDsaKeyFormat{
					Version: 0,
					Params: &slhdsapb.SlhDsaParams{
						KeySize:  64,
						HashType: slhdsapb.SlhDsaHashType_SHA2,
						SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
					},
				}),
			},
		},
		{
			name: "invalid version",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &slhdsapb.SlhDsaKeyFormat{
					Version: 1,
					Params: &slhdsapb.SlhDsaParams{
						KeySize:  64,
						HashType: slhdsapb.SlhDsaHashType_SHA2,
						SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
					},
				}),
			},
		},
		{
			name: "invalid value",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value:            []byte("invalid_value"),
			},
		},
		{
			name: "invalid hash type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &slhdsapb.SlhDsaKeyFormat{
					Version: 0,
					Params: &slhdsapb.SlhDsaParams{
						KeySize:  64,
						HashType: slhdsapb.SlhDsaHashType_SHAKE,
						SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
					},
				}),
			},
		},
		{
			name: "invalid key size",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &slhdsapb.SlhDsaKeyFormat{
					Version: 0,
					Params: &slhdsapb.SlhDsaParams{
						KeySize:  128,
						HashType: slhdsapb.SlhDsaHashType_SHA2,
						SigType:  slhdsapb.SlhDsaSignatureType_SMALL_SIGNATURE,
					},
				}),
			},
		},
		{
			name: "invalid signature type",
			template: &tinkpb.KeyTemplate{
				TypeUrl:          "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey",
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				Value: mustMarshal(t, &slhdsapb.SlhDsaKeyFormat{
					Version: 0,
					Params: &slhdsapb.SlhDsaParams{
						KeySize:  64,
						HashType: slhdsapb.SlhDsaHashType_SHA2,
						SigType:  slhdsapb.SlhDsaSignatureType_FAST_SIGNING,
					},
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.ParseParameters(tc.template); err == nil {
				t.Errorf("protoserialization.ParseParameters(%v) err = nil, want error", tc.template)
			}
		})
	}
}
