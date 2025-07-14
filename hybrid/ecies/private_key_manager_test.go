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

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	eahpb "github.com/tink-crypto/tink-go/v2/proto/ecies_aead_hkdf_go_proto"
)

const (
	privateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"
	privateKeyVersion = 0
)

func TestPrivateKeyManagerPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	serializedPrivateKey := mustMarshal(t, makeValidECIESAEADHKDFPrivateKey(t))

	primitive, err := km.Primitive(serializedPrivateKey)
	if err != nil {
		t.Fatalf("km.Primitive(serilizedPrivateKey) err = %v, want nil", err)
	}
	if _, ok := primitive.(tink.HybridDecrypt); !ok {
		t.Errorf("primitive is of type %T, want %T", primitive, (tink.HybridDecrypt)(nil))
	}
}

func TestPrivateKeyManagerPrimitiveErrors(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
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
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.Version = privateKeyVersion + 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "invalid_private_key_version",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.GetPublicKey().Version = privateKeyVersion + 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_public_key",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.PublicKey = nil
				return mustMarshal(t, k)
			}(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.Primitive(tc.key); err == nil {
				t.Fatalf("km.Primitive(serilizedPrivateKey) err = nil, want non-nil")
			}
		})
	}
}

func TestPrivateKeyManagerGetPublicKeyErrors(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
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
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.Version = privateKeyVersion + 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "invalid_private_key_version",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.GetPublicKey().Version = privateKeyVersion + 1
				return mustMarshal(t, k)
			}(),
		},
		{
			name: "nil_public_key",
			key: func() []byte {
				k := makeValidECIESAEADHKDFPrivateKey(t)
				k.PublicKey = nil
				return mustMarshal(t, k)
			}(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.(registry.PrivateKeyManager).PublicKeyData(tc.key); err == nil {
				t.Fatalf("km.PublicKeyData(serilizedPrivateKey) err = nil, want non-nil")
			}
		})
	}
}

func TestPrivateKeyManagerNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}
	serializedKeyFormat := mustMarshal(t, makeValidECIESAEADHKDFKeyFormat(t))

	if _, err := km.NewKey(serializedKeyFormat); err != nil {
		t.Errorf("km.NewKey(serializedKeyFormat) err = %v, want nil", err)
	}
	if _, err := km.NewKeyData(serializedKeyFormat); err != nil {
		t.Errorf("km.NewKeyData(serializedKeyFormat) err = %v, want nil", err)
	}
}

func TestPrivateKeyManagerNewKeyErrors(t *testing.T) {
	km, err := registry.GetKeyManager(privateKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", privateKeyTypeURL, err)
	}

	testCases := []struct {
		name      string
		keyFormat []byte
	}{
		{
			name:      "nil_keyFormat",
			keyFormat: nil,
		},
		{
			name: "nil_params",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.Params = nil
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "nil_kem_params",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().KemParams = nil
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "nil_dem_params",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().DemParams = nil
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "unknown_kem_curve_type",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().GetKemParams().CurveType = commonpb.EllipticCurveType_UNKNOWN_CURVE
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "unknown_kem_hash_type",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().GetKemParams().HkdfHashType = commonpb.HashType_UNKNOWN_HASH
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "nil_dem_aead",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().GetDemParams().AeadDem = nil
				return mustMarshal(t, kf)
			}(),
		},
		{
			name: "unknown_point_format",
			keyFormat: func() []byte {
				kf := makeValidECIESAEADHKDFKeyFormat(t)
				kf.GetParams().EcPointFormat = commonpb.EcPointFormat_UNKNOWN_FORMAT
				return mustMarshal(t, kf)
			}(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.NewKey(tc.keyFormat); err == nil {
				t.Errorf("km.NewKey(tc.keyFormat) err == nil, want non-nil")
			}
			if _, err := km.NewKeyData(tc.keyFormat); err == nil {
				t.Errorf("km.NewKeyData(tc.keyFormat) err == nil, want non-nil")
			}
		})
	}
}

func makeValidECIESAEADHKDFKeyFormat(t *testing.T) *eahpb.EciesAeadHkdfKeyFormat {
	t.Helper()
	return &eahpb.EciesAeadHkdfKeyFormat{
		Params: &eahpb.EciesAeadHkdfParams{
			KemParams: &eahpb.EciesHkdfKemParams{
				CurveType:    commonpb.EllipticCurveType_NIST_P256,
				HkdfHashType: commonpb.HashType_SHA256,
				HkdfSalt:     []byte{},
			},
			DemParams: &eahpb.EciesAeadDemParams{
				AeadDem: aead.AES128GCMKeyTemplate(),
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}
}

func makeValidECIESAEADHKDFPrivateKey(t *testing.T) *eahpb.EciesAeadHkdfPrivateKey {
	t.Helper()
	keyFormat := makeValidECIESAEADHKDFKeyFormat(t)
	curve, err := subtle.GetCurve(keyFormat.GetParams().GetKemParams().GetCurveType().String())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Fatal(err)
	}
	return &eahpb.EciesAeadHkdfPrivateKey{
		Version:  privateKeyVersion,
		KeyValue: privateKey.D.Bytes(),
		PublicKey: &eahpb.EciesAeadHkdfPublicKey{
			Version: 0,
			Params:  keyFormat.GetParams(),
			X:       privateKey.PublicKey.Point.X.Bytes(),
			Y:       privateKey.PublicKey.Point.Y.Bytes(),
		},
	}
}

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	serialized, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) err = %v, want nil", msg, err)
	}
	return serialized
}
