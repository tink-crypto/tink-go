// Copyright 2019 Google LLC
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

package aessiv_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	aspb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestKeyManagerPrimitive(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AESSIV key manager: %s", err)
	}

	protoKey := mustMarshal(t, &aspb.AesSivKeyFormat{
		Version: testutil.AESSIVKeyVersion,
		KeySize: subtle.AESSIVKeySize,
	})
	m, err := km.NewKey(protoKey)
	if err != nil {
		t.Fatalf("km.NewKey(protoKey) = _, %v; want _, nil", err)
	}
	key, ok := m.(*aspb.AesSivKey)
	if !ok {
		t.Fatalf("m is not *aspb.AesSivKey")
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() = %q; want nil", err)
	}
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Fatalf("km.Primitive(%v) = %v; want nil", serializedKey, err)
	}

	keyManagerPrimitive, ok := p.(tink.DeterministicAEAD)
	if !ok {
		t.Fatalf("Primitive() = %T, want tink.AEAD", p)
	}
	expectedPrimitive, err := subtle.NewAESSIV(key.GetKeyValue())
	if err != nil {
		t.Fatalf("subtle.NewAESSIV() err = %q, want nil", err)
	}
	if err := encryptDecrypt(keyManagerPrimitive, expectedPrimitive); err != nil {
		t.Errorf("encryptDecrypt(keyManagerPrimitive, expectedPrimitive) err = %v, want nil", err)
	}
	if err := encryptDecrypt(expectedPrimitive, keyManagerPrimitive); err != nil {
		t.Errorf("encryptDecrypt(expectedPrimitive, keyManagerPrimitive) err = %v, want nil", err)
	}
}

func TestKeyManagerPrimitiveWithInvalidKeys(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	invalidKeys := []*aspb.AesSivKey{
		// Bad key size.
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(16),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(32),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(63),
		},
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion,
			KeyValue: random.GetRandomBytes(65),
		},
		// Bad version.
		&aspb.AesSivKey{
			Version:  testutil.AESSIVKeyVersion + 1,
			KeyValue: random.GetRandomBytes(subtle.AESSIVKeySize),
		},
	}
	for _, key := range invalidKeys {
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() = %q; want nil", err)
		}
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive(%v) = _, nil; want _, err", serializedKey)
		}
	}
}

func TestKeyManagerNewKey(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AESSIV key manager: %s", err)
	}
	protoKey := mustMarshal(t, &aspb.AesSivKeyFormat{
		Version: testutil.AESSIVKeyVersion,
		KeySize: subtle.AESSIVKeySize,
	})
	m, err := km.NewKey(protoKey)
	if err != nil {
		t.Fatalf("km.NewKey(protoKey) = _, %v; want _, nil", err)
	}
	key, ok := m.(*aspb.AesSivKey)
	if !ok {
		t.Fatalf("m is not *aspb.AesSivKey")
	}
	if err := validateAESSIVKey(key); err != nil {
		t.Errorf("validateAESSIVKey(%v) = %v; want nil", key, err)
	}
}

func TestKeyManagerNewKeyData(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AESSIV key manager: %s", err)
	}
	protoKey := mustMarshal(t, &aspb.AesSivKeyFormat{
		Version: testutil.AESSIVKeyVersion,
		KeySize: subtle.AESSIVKeySize,
	})
	kd, err := km.NewKeyData(protoKey)
	if err != nil {
		t.Fatalf("km.NewKeyData(protoKey) = _, %v; want _, nil", err)
	}
	if kd.TypeUrl != testutil.AESSIVTypeURL {
		t.Fatalf("TypeUrl: %v != %v", kd.TypeUrl, testutil.AESSIVTypeURL)
	}
	if kd.KeyMaterialType != tpb.KeyData_SYMMETRIC {
		t.Fatalf("KeyMaterialType: %v != SYMMETRIC", kd.KeyMaterialType)
	}
	key := new(aspb.AesSivKey)
	if err := proto.Unmarshal(kd.Value, key); err != nil {
		t.Fatalf("proto.Unmarshal(%v, key) = %v; want nil", kd.Value, err)
	}
	if err := validateAESSIVKey(key); err != nil {
		t.Errorf("validateAESSIVKey(%v) = %v; want nil", key, err)
	}
}

func TestKeyManagerNewKeyInvalid(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) err = %v, want nil", testutil.AESSIVTypeURL, err)
	}
	invalidKeySize, err := proto.Marshal(&aspb.AesSivKeyFormat{
		KeySize: subtle.AESSIVKeySize - 1,
		Version: testutil.AESSIVKeyVersion,
	})
	if err != nil {
		t.Errorf("proto.Marshal() err = %v, want nil", err)
	}
	// Proto messages start with a VarInt, which always ends with a byte with the
	// MSB unset, so 0x80 is invalid.
	invalidSerialization, err := hex.DecodeString("80")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	for _, test := range []struct {
		name      string
		keyFormat []byte
	}{
		{
			name:      "invalid key size",
			keyFormat: invalidKeySize,
		},
		{
			name:      "invalid serialization",
			keyFormat: invalidSerialization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err = km.NewKey(test.keyFormat); err == nil {
				t.Error("km.NewKey() err = nil, want non-nil")
			}
		})
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	if !km.DoesSupport(testutil.AESSIVTypeURL) {
		t.Errorf("AESSIVKeyManager must support %s", testutil.AESSIVTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("AESSIVKeyManager must only support %s", testutil.AESSIVTypeURL)
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESSIVTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AESSIV key manager: %s", err)
	}
	if kt := km.TypeURL(); kt != testutil.AESSIVTypeURL {
		t.Errorf("km.TypeURL() = %s; want %s", kt, testutil.AESSIVTypeURL)
	}
}

func validateAESSIVKey(key *aspb.AesSivKey) error {
	if key.Version != testutil.AESSIVKeyVersion {
		return fmt.Errorf("incorrect key version: keyVersion != %d", testutil.AESSIVKeyVersion)
	}
	if uint32(len(key.KeyValue)) != subtle.AESSIVKeySize {
		return fmt.Errorf("incorrect key size: keySize != %d", subtle.AESSIVKeySize)
	}

	// Try to encrypt and decrypt.
	p, err := subtle.NewAESSIV(key.KeyValue)
	if err != nil {
		return fmt.Errorf("invalid key: %v", key.KeyValue)
	}
	return encryptDecrypt(p, p)
}

func encryptDecrypt(encryptor, decryptor tink.DeterministicAEAD) error {
	// Try to encrypt and decrypt random data.
	plaintext := random.GetRandomBytes(32)
	associatedData := random.GetRandomBytes(32)
	ciphertext, err := encryptor.EncryptDeterministically(plaintext, associatedData)
	if err != nil {
		return fmt.Errorf("encryptor.EncryptDeterministically() err = %v, want nil", err)
	}
	decrypted, err := decryptor.DecryptDeterministically(ciphertext, associatedData)
	if err != nil {
		return fmt.Errorf("decryptor.DecryptDeterministically() err = %v, want nil", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		return fmt.Errorf("decryptor.DecryptDeterministically() = %v, want %v", decrypted, plaintext)
	}
	return nil
}
