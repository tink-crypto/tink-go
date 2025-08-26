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
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/tink"
	slhdsapb "github.com/tink-crypto/tink-go/v2/proto/slh_dsa_go_proto"
)

func TestVerifierKeyManagerGetPrimitiveBasic(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashType tinkslhdsa.HashType
		keySize  int
		sigType  tinkslhdsa.SignatureType
		pub      []byte
		sig      []byte
		msg      []byte
	}{
		{
			name:     "SLH-DSA-SHA2-128s",
			hashType: tinkslhdsa.SHA2,
			keySize:  64,
			sigType:  tinkslhdsa.SmallSignature,
			pub:      mustDecodeString(t, pubKeySHA2128sHex),
			sig:      mustDecodeString(t, sigSHA2128sHex),
			msg:      mustDecodeString(t, msgSHA2128sHex),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPublicKey")
			if err != nil {
				t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey", err)
			}
			params, err := tinkslhdsa.NewParameters(tc.hashType, tc.keySize, tc.sigType, tinkslhdsa.VariantNoPrefix)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewParameters(%v) err = %v, want nil", tinkslhdsa.VariantNoPrefix, err)
			}
			publicKey, err := tinkslhdsa.NewPublicKey(tc.pub, 0, params)
			if err != nil {
				t.Fatalf("tinkslhdsa.NewPublicKey(%v, %v, %v) err = %v, want nil", tc.pub, 0, params, err)
			}
			keySerialization, err := protoserialization.SerializeKey(publicKey)
			if err != nil {
				t.Fatalf("protoserialization.SerializeKey(%v) err = %v, want nil", publicKey, err)
			}
			p, err := km.Primitive(keySerialization.KeyData().GetValue())
			if err != nil {
				t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) err = %v, want nil", err)
			}
			v, ok := p.(tink.Verifier)
			if !ok {
				t.Fatalf("km.Primitive(keySerialization.KeyData().GetValue()) = %T, want %T", p, (tink.Verifier)(nil))
			}
			if err := v.Verify(tc.sig, tc.msg); err != nil {
				t.Errorf("v.Verify(%x, %x) err = %v, want nil", tc.sig, tc.msg, err)
			}
		})
	}
}

func TestVerifierKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager("type.googleapis.com/google.crypto.tink.SlhDsaPublicKey")
	if err != nil {
		t.Errorf("cannot obtain SLHDSAVerifier key manager: %s", err)
	}

	// invalid version
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := newSLHDSAPublicKey(tc.hashType, tc.keySize, tc.sigType)
			key.Version = 1
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %q, want nil", err)
			}
			if _, err := km.Primitive(serializedKey); err == nil {
				t.Errorf("expect an error when version is invalid")
			}
		})
	}

	// nil input
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty slice")
	}
}

func newSLHDSAPublicKey(hashType tinkslhdsa.HashType, keySize int, sigType tinkslhdsa.SignatureType) *slhdsapb.SlhDsaPublicKey {
	return newSLHDSAPrivateKey(hashType, keySize, sigType).PublicKey
}

func mustDecodeString(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) failed: %v", s, err)
	}
	return b
}
