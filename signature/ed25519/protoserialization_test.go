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

package ed25519

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func newKeySerialization(t *testing.T, keyData *tinkpb.KeyData, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func TestParsePublicKeyFails(t *testing.T) {
	protoPublicKey := ed25519pb.Ed25519PublicKey{
		KeyValue: []byte("12345678901234567890123456789012"),
		Version:  publicKeyProtoVersion,
	}
	serializedProtoPublicKey, err := proto.Marshal(&protoPublicKey)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKey) err = %v, want nil", err)
	}
	protoPublicKeyWithWrongVersion := ed25519pb.Ed25519PublicKey{
		KeyValue: []byte("12345678901234567890123456789012"),
		Version:  publicKeyProtoVersion + 1,
	}
	serializedProtoPublicKeyWithWrongVersion, err := proto.Marshal(&protoPublicKeyWithWrongVersion)
	if err != nil {
		t.Fatalf("proto.Marshal(protoPublicKeyWithWrongVersion) err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name             string
		keySerialization *protoserialization.KeySerialization
	}{
		{
			name:             "key data is nil",
			keySerialization: newKeySerialization(t, nil, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong type URL",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         "invalid_type_url",
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key material type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name: "wrong key version",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
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
	protoPublicKey := ed25519pb.Ed25519PublicKey{
		KeyValue: []byte("12345678901234567890123456789012"),
		Version:  publicKeyProtoVersion,
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
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
			wantVariant: VariantTink,
		},
		{
			name: "key with LEGACY output prefix type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
			wantVariant: VariantLegacy,
		},
		{
			name: "key with CRUNCHY output prefix type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
			wantVariant: VariantCrunchy,
		},
		{
			name: "key with RAW output prefix type",
			keySerialization: newKeySerialization(t, &tinkpb.KeyData{
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
				t.Errorf("p.ParseKey(%v) err = %v, want non-nil", tc.keySerialization, err)
			}
			wantParams, err := NewParameters(tc.wantVariant)
			if err != nil {
				t.Fatalf("NewParameters(%v) err = %v, want nil", tc.wantVariant, err)
			}
			idRequirement, _ := tc.keySerialization.IDRequirement()
			wantKey, err := NewPublicKey(protoPublicKey.GetKeyValue(), idRequirement, wantParams)
			if err != nil {
				t.Fatalf("NewPublicKey(%v, %v, %v) err = %v, want nil", protoPublicKey.GetKeyValue(), idRequirement, wantParams, err)
			}
			if !gotKey.Equals(wantKey) {
				t.Errorf("%v.Equals(%v) = false, want true", gotKey, wantKey)
			}
			// Test serialization returns back tc.keySerialization.
			s := publicKeySerializer{}
			keySerialization, err := s.SerializeKey(gotKey)
			if err != nil {
				t.Fatalf("s.SerializeKey(gotKey) err = %v, want nil", err)
			}
			if got, want := keySerialization, tc.keySerialization; !got.Equals(want) {
				t.Errorf("s.SerializeKey(gotKey) = %v, want %v", got, want)
			}
		})
	}
}

type testParams struct{}

func (p *testParams) HasIDRequirement() bool { return true }

func (p *testParams) Equals(params key.Parameters) bool { return true }

type testKey struct{}

func (k *testKey) Parameters() key.Parameters { return &testParams{} }

func (k *testKey) Equals(other key.Key) bool { return true }

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
			name:      "invlid public key",
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

func newPublicKey(t *testing.T, keyBytes []byte, idRequirement uint32, variant Variant) *PublicKey {
	t.Helper()
	params, err := NewParameters(variant)
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
	protoPublicKey := ed25519pb.Ed25519PublicKey{
		KeyValue: []byte("12345678901234567890123456789012"),
		Version:  publicKeyProtoVersion,
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
			publicKey: newPublicKey(t, []byte("12345678901234567890123456789012"), 12345, VariantTink),
			want: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_TINK, 12345),
		},
		{
			name:      "Public key with LEGACY output prefix type",
			publicKey: newPublicKey(t, []byte("12345678901234567890123456789012"), 12345, VariantLegacy),
			want: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_LEGACY, 12345),
		},
		{
			name:      "Public key with CRUNCHY output prefix type",
			publicKey: newPublicKey(t, []byte("12345678901234567890123456789012"), 12345, VariantCrunchy),
			want: newKeySerialization(t, &tinkpb.KeyData{
				TypeUrl:         verifierTypeURL,
				Value:           serializedProtoPublicKey,
				KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
			}, tinkpb.OutputPrefixType_CRUNCHY, 12345),
		},
		{
			name:      "Public key with RAW output prefix type",
			publicKey: newPublicKey(t, []byte("12345678901234567890123456789012"), 0, VariantNoPrefix),
			want: newKeySerialization(t, &tinkpb.KeyData{
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
			if !got.Equals(tc.want) {
				t.Errorf("s.SerializeKey(%v) = %v, want %v", tc.publicKey, got, tc.want)
			}
		})
	}
}
