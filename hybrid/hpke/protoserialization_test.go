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

package hpke_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	hpkepb "github.com/tink-crypto/tink-go/v2/proto/hpke_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

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
			name:      "nil key",
			publicKey: nil,
		},
		{
			name:      "invalid public key",
			publicKey: &hpke.PublicKey{},
		},
		{
			name:      "incorrect key type",
			publicKey: &testKey{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := protoserialization.SerializeKey(tc.publicKey); err == nil {
				t.Errorf("protoserialization.SerializeKey(%v) err = nil, want non-nil", tc.publicKey)
			}
		})
	}
}

type protoSerializationTestCase struct {
	name                   string
	publicKey              *hpke.PublicKey
	publicKeySerialization *protoserialization.KeySerialization
}

func mustCreateKeySerialization(t *testing.T, url string, keyMaterialType tinkpb.KeyData_KeyMaterialType, keyMessage proto.Message, outputPrefixType tinkpb.OutputPrefixType, idRequirement uint32) *protoserialization.KeySerialization {
	t.Helper()
	serializedKey, err := proto.Marshal(keyMessage)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", keyMessage, err)
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         url,
		Value:           serializedKey,
		KeyMaterialType: keyMaterialType,
	}
	ks, err := protoserialization.NewKeySerialization(keyData, outputPrefixType, idRequirement)
	if err != nil {
		t.Fatalf("protoserialization.NewKeySerialization(%v, %v, %v) err = %v, want nil", keyData, outputPrefixType, idRequirement, err)
	}
	return ks
}

func mustCreateTestCases(t *testing.T) []protoSerializationTestCase {
	t.Helper()

	p256PublicKeyBytes := mustHexDecode(t, p256SHA256PublicKeyBytesHex)
	p384PublicKeyBytes := mustHexDecode(t, p384PublicKeyBytesHex)
	p521PublicKeyBytes := mustHexDecode(t, p521SHA512PublicKeyBytesHex)
	x25519PublicKeyBytes := mustHexDecode(t, x25519PublicKeyBytesHex)

	testCases := []protoSerializationTestCase{}
	for _, aeadID := range []struct {
		enumAEADID  hpke.AEADID
		protoAEADID hpkepb.HpkeAead
	}{
		{hpke.AES128GCM, hpkepb.HpkeAead_AES_128_GCM},
		{hpke.AES256GCM, hpkepb.HpkeAead_AES_256_GCM},
		{hpke.ChaCha20Poly1305, hpkepb.HpkeAead_CHACHA20_POLY1305},
	} {
		for _, kdfID := range []struct {
			enumKDFID  hpke.KDFID
			protoKDFID hpkepb.HpkeKdf
		}{
			{hpke.HKDFSHA256, hpkepb.HpkeKdf_HKDF_SHA256},
			{hpke.HKDFSHA384, hpkepb.HpkeKdf_HKDF_SHA384},
			{hpke.HKDFSHA512, hpkepb.HpkeKdf_HKDF_SHA512},
		} {
			for _, variant := range []struct {
				enumVariant  hpke.Variant
				protoVariant tinkpb.OutputPrefixType
			}{
				{hpke.VariantTink, tinkpb.OutputPrefixType_TINK},
				{hpke.VariantCrunchy, tinkpb.OutputPrefixType_CRUNCHY},
				{hpke.VariantNoPrefix, tinkpb.OutputPrefixType_RAW},
			} {
				idRequirement := uint32(0x01020304)
				if variant.enumVariant == hpke.VariantNoPrefix {
					idRequirement = 0
				}
				for _, kemIDAndKeyBytes := range []struct {
					enumKEMID      hpke.KEMID
					protoKEMID     hpkepb.HpkeKem
					publicKeyBytes []byte
				}{
					{hpke.DHKEM_P256_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_P256_HKDF_SHA256, p256PublicKeyBytes},
					{hpke.DHKEM_P384_HKDF_SHA384, hpkepb.HpkeKem_DHKEM_P384_HKDF_SHA384, p384PublicKeyBytes},
					{hpke.DHKEM_P521_HKDF_SHA512, hpkepb.HpkeKem_DHKEM_P521_HKDF_SHA512, p521PublicKeyBytes},
					{hpke.DHKEM_X25519_HKDF_SHA256, hpkepb.HpkeKem_DHKEM_X25519_HKDF_SHA256, x25519PublicKeyBytes},
				} {
					publicKey := mustCreatePublicKey(t, kemIDAndKeyBytes.publicKeyBytes, idRequirement, mustCreateParameters(t, hpke.ParametersOpts{
						KEMID:   kemIDAndKeyBytes.enumKEMID,
						KDFID:   kdfID.enumKDFID,
						AEADID:  aeadID.enumAEADID,
						Variant: variant.enumVariant,
					}))
					publicKeySerialization := mustCreateKeySerialization(t, "type.googleapis.com/google.crypto.tink.HpkePublicKey", tinkpb.KeyData_ASYMMETRIC_PUBLIC,
						&hpkepb.HpkePublicKey{
							Version: 0,
							Params: &hpkepb.HpkeParams{
								Kem:  kemIDAndKeyBytes.protoKEMID,
								Kdf:  kdfID.protoKDFID,
								Aead: aeadID.protoAEADID,
							},
							PublicKey: kemIDAndKeyBytes.publicKeyBytes,
						}, variant.protoVariant, idRequirement)
					testCases = append(testCases, protoSerializationTestCase{
						name:                   fmt.Sprintf("%s-%s-%s-%s", kemIDAndKeyBytes.enumKEMID, kdfID.enumKDFID, aeadID.enumAEADID, variant.enumVariant),
						publicKey:              publicKey,
						publicKeySerialization: publicKeySerialization,
					})
				}
			}
		}
	}
	return testCases
}

func TestSerializePublicKey(t *testing.T) {
	for _, tc := range mustCreateTestCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protoserialization.SerializeKey(tc.publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", tc.publicKey, err)
			}
			if diff := cmp.Diff(got, tc.publicKeySerialization); diff != "" {
				t.Errorf("protoserialization.SerializeKey(%v) returned unexpected diff (-want +got):\n%s", tc.publicKey, diff)
			}
		})
	}
}
