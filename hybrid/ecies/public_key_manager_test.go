// Copyright 2023 Google LLC
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

package ecies_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eahpb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
)

const (
	publicKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"
	publicKeyVersion = 0
)

func TestPublicKeyManagerPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}
	serializedPublicKey := mustMarshal(t, makeValidECIESAEADHKDFPublicKey(t))

	primitive, err := km.Primitive(serializedPublicKey)
	if err != nil {
		t.Fatalf("km.Primitive(serilizedPublicKey) err = %v, want nil", err)
	}
	if _, ok := primitive.(tink.HybridEncrypt); !ok {
		t.Errorf("primitive is of type %T, want %T", primitive, (tink.HybridEncrypt)(nil))
	}
}

func TestPublicKeyManagerPrimitiveErrors(t *testing.T) {
	km, err := registry.GetKeyManager(publicKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", publicKeyTypeURL, err)
	}

	testCases := []struct {
		name string
		key  []byte
	}{
		{
			name: "nil_key",
			key:  nil,
		},
		{
			name: "invalid_version",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.Version = publicKeyVersion + 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_params",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.Params = nil
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_kem_params",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().KemParams = nil
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_dem_params",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().DemParams = nil
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "unknown_kem_curve_type",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().GetKemParams().CurveType = commonpb.EllipticCurveType_UNKNOWN_CURVE
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "unknown_kem_hash_type",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().GetKemParams().HkdfHashType = commonpb.HashType_UNKNOWN_HASH
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_dem_aead",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().GetDemParams().AeadDem = nil
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "unknown_point_format",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPublicKey(t)
				k.GetParams().EcPointFormat = commonpb.EcPointFormat_UNKNOWN_FORMAT
				return mustMarshal(t, k)
			}(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.Primitive(tc.key); err == nil {
				t.Fatalf("km.Primitive(serilizedPublicKey) err = nil, want non-nil")
			}
		})
	}

}

func makeValidECIESAEADHKDFPublicKey(t *testing.T) *eahpb.EciesAeadHkdfPublicKey {
	t.Helper()
	privateKey := makeValidECIESAEADHKDFPrivateKey(t)
	return privateKey.GetPublicKey()
}
