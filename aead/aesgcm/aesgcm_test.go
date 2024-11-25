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

package aesgcm_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestGetKeyFromHandle(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*aesgcm.Key)
	if !ok {
		t.Errorf("entry.Key() is not an *Key")
	}
	keySize := 16
	opts := aesgcm.ParametersOpts{
		KeySizeInBytes: keySize,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	}
	expectedParameters, err := aesgcm.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
	}
	if !key.Parameters().Equals(expectedParameters) {
		t.Errorf("key.Parameters().Equals(expectedParameters) = false, want true")
	}
	if _, hasIDRequirement := key.IDRequirement(); !hasIDRequirement {
		t.Errorf("expected ID requirement, got none")
	}
	keyBytes := key.KeyBytes()
	if keyBytes.Len() != keySize {
		t.Errorf("keyBytes.Len() = %v, want %v", keyBytes.Len(), keySize)
	}
}

func TestCreateKeysetHandleFromKey(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	aeadPrimitive, err := aead.New(keysetHandle)
	if err != nil {
		t.Fatalf("aead.New(keysetHandle) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	additionalData := []byte("additionalData")
	ciphertext, err := aeadPrimitive.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Encrypt(%v, %v) err = %v, want nil", plaintext, additionalData, err)
	}

	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*aesgcm.Key)
	if !ok {
		t.Errorf("entry.Key() is not *aesgcm.Key")
	}

	// Create a new keyset handle with the same key.
	manager := keyset.NewManager()
	keyID, err := manager.AddKey(key)
	if err != nil {
		t.Fatalf("manager.AddKey(key) err = %v, want nil", err)
	}
	if err = manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	newHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	// Get an AEAD primitive from the new handle and decrypt the ciphertext.
	newAEAD, err := aead.New(newHandle)
	if err != nil {
		t.Fatalf("aead.New(newHandle) err = %v, want nil", err)
	}
	decrypt, err := newAEAD.Decrypt(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("decrypt.New(otherAEADPrimitivce, %v, %v) err = %v, want nil", ciphertext, additionalData, err)
	}
	if !bytes.Equal(decrypt, plaintext) {
		t.Errorf("decrypt = %v, want %v", decrypt, plaintext)
	}
}

func TestCreateKeysetHandleFromParameters(t *testing.T) {
	opts := aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantTink,
	}
	params, err := aesgcm.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
	}
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	manager.SetPrimary(keyID)
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	aeadPrimitive, err := aead.New(handle)
	if err != nil {
		t.Fatalf("aead.New(handle) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	additionalData := []byte("additionalData")
	ciphertext, err := aeadPrimitive.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Encrypt(%v, %v) err = %v, want nil", plaintext, additionalData, err)
	}
	decrypted, err := aeadPrimitive.Decrypt(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Decrypt(%v, %v) err = %v, want nil", ciphertext, additionalData, err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %v, want %v", decrypted, plaintext)
	}
}

func mustDecodeHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	x, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(%v) err = %v, want nil", hexStr, err)
	}
	return x
}

func mustCreateKey(t *testing.T, keyValue []byte, keyID uint32, opts aesgcm.ParametersOpts) *aesgcm.Key {
	t.Helper()
	params, err := aesgcm.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesgcm.NewParameters(%v) err = %v, want nil", opts, err)
	}
	keyBytes := secretdata.NewBytesFromData(keyValue, insecuresecretdataaccess.Token{})
	key, err := aesgcm.NewKey(keyBytes, keyID, params)
	if err != nil {
		t.Fatalf("aesgcm.NewKey(%v, %v, %v) err = %v, want nil", keyBytes, keyID, params, err)
	}
	return key
}

func TestAESGCMAEADWorks(t *testing.T) {
	// Test vectors from
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/aes_gcm_test.json.
	// 16 bytes key.
	key1 := mustDecodeHex(t, "5b9604fe14eadba931b0ccf34843dab9")
	ciphertext1 := mustDecodeHex(t, "028318abc1824029138141a226073cc1d851beff176384dc9896d5ff0a3ea7a5487cb5f7d70fb6c58d038554")
	wantMessage1 := mustDecodeHex(t, "001d0c231287c1182784554ca3a21908")
	// 32 bytes key.
	key2 := mustDecodeHex(t, "51e4bf2bad92b7aff1a4bc05550ba81df4b96fabf41c12c7b00e60e48db7e152")
	ciphertext2 := mustDecodeHex(t, "4f07afedfdc3b6c2361823d3cf332a12fdee800b602e8d7c4799d62c140c9bb834876b09")
	wantMessage2 := mustDecodeHex(t, "be3308f72a2c6aed")

	tinkPrefix := []byte{cryptofmt.TinkStartByte, 0x22, 0x34, 0x55, 0xab}
	crunchyPrefix := []byte{cryptofmt.LegacyStartByte, 0x22, 0x34, 0x55, 0xab}

	for _, tc := range []struct {
		name          string
		key           *aesgcm.Key
		ciphertext    []byte
		wantPlaintext []byte
	}{
		{
			name: fmt.Sprintf("AES-%d-TINK", len(key1)*8),
			key: mustCreateKey(t, key1, 0x223455ab, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			}),
			ciphertext:    slices.Concat(tinkPrefix, ciphertext1),
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("AES-%d-CRUNCHY", len(key1)*8),
			key: mustCreateKey(t, key1, 0x223455ab, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantCrunchy,
			}),
			ciphertext:    slices.Concat(crunchyPrefix, ciphertext1),
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("AES-%d-RAW", len(key1)*8),
			key: mustCreateKey(t, key1, 0, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key1),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantNoPrefix,
			}),
			ciphertext:    ciphertext1,
			wantPlaintext: wantMessage1,
		},
		{
			name: fmt.Sprintf("AES-%d-TINK", len(key2)*8),
			key: mustCreateKey(t, key2, 0x223455ab, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantTink,
			}),
			ciphertext:    slices.Concat(tinkPrefix, ciphertext2),
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("AES-%d-CRUNCHY", len(key2)*8),
			key: mustCreateKey(t, key2, 0x223455ab, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantCrunchy,
			}),
			ciphertext:    slices.Concat(crunchyPrefix, ciphertext2),
			wantPlaintext: wantMessage2,
		},
		{
			name: fmt.Sprintf("AES-%d-RAW", len(key2)*8),
			key: mustCreateKey(t, key2, 0, aesgcm.ParametersOpts{
				KeySizeInBytes: len(key2),
				IVSizeInBytes:  12,
				TagSizeInBytes: 16,
				Variant:        aesgcm.VariantNoPrefix,
			}),
			ciphertext:    ciphertext2,
			wantPlaintext: wantMessage2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// From the key.
			a1, err := aesgcm.NewAEAD(tc.key)
			if err != nil {
				t.Fatalf("aesgcm.NewAEAD(tc.key) err = %v, want nil", err)
			}

			// From the keyset handle.
			a2 := func() tink.AEAD {
				km := keyset.NewManager()
				keyID, err := km.AddKey(tc.key)
				if err != nil {
					t.Fatalf("km.AddKey(tc.key) err = %v, want nil", err)
				}
				if err := km.SetPrimary(keyID); err != nil {
					t.Fatalf("km.SetPrimary(keyID) err = %v, want nil", err)
				}
				kh, err := km.Handle()
				if err != nil {
					t.Fatalf("km.Handle() err = %v, want nil", err)
				}
				a, err := aead.New(kh)
				if err != nil {
					t.Fatalf("New(kh) err = %v, want nil", err)
				}
				return a
			}()

			for _, a := range []tink.AEAD{a1, a2} {
				decrypted, err := a.Decrypt(tc.ciphertext, nil)
				if err != nil {
					t.Fatalf("a.Decrypt(tc.ciphertext, nil) err = %v, want nil", err)
				}
				if !bytes.Equal(decrypted, tc.wantPlaintext) {
					t.Errorf("a.Decrypt(tc.ciphertext, nil) = %v, want %v", decrypted, tc.wantPlaintext)
				}
			}
		})
	}
}

type stubConfig struct {
	keyManagers           map[string]registry.KeyManager
	primitiveConstructors map[reflect.Type]func(key key.Key) (any, error)
}

func newStubConfig() *stubConfig {
	return &stubConfig{make(map[string]registry.KeyManager), make(map[reflect.Type]func(key key.Key) (any, error))}
}

func (sc *stubConfig) RegisterKeyManager(keyTypeURL string, km registry.KeyManager, _ internalapi.Token) error {
	sc.keyManagers[keyTypeURL] = km
	return nil
}

func (sc *stubConfig) RegisterPrimitiveConstructor(keyType reflect.Type, primitiveConstructor func(key key.Key) (any, error), _ internalapi.Token) error {
	sc.primitiveConstructors[keyType] = primitiveConstructor
	return nil
}

type alwaysFailingStubConfig struct{}

func (sc *alwaysFailingStubConfig) RegisterKeyManager(keyTypeURL string, km registry.KeyManager, _ internalapi.Token) error {
	return fmt.Errorf("oh no :(")
}

func (sc *alwaysFailingStubConfig) RegisterPrimitiveConstructor(keyType reflect.Type, primitiveConstructor func(key key.Key) (any, error), _ internalapi.Token) error {
	return fmt.Errorf("oh no :(")
}

func TestRegisterKeyManager(t *testing.T) {
	sc := newStubConfig()
	if len(sc.keyManagers) != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", len(sc.keyManagers))
	}

	err := aesgcm.RegisterKeyManager(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("RegisterKeyManager() err = %v, want nil", err)
	}

	if len(sc.keyManagers) != 1 {
		t.Errorf("Number of registered key types = %d, want 1", len(sc.keyManagers))
	}
	if _, ok := sc.keyManagers[testutil.AESGCMTypeURL]; !ok {
		t.Errorf("RegisterKeyManager() registered wrong type URL, want %q", testutil.AESGCMTypeURL)
	}
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	sc := newStubConfig()
	if len(sc.keyManagers) != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", len(sc.keyManagers))
	}

	err := aesgcm.RegisterPrimitiveConstructor(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	if len(sc.keyManagers) != 0 {
		t.Errorf("Number of registered key managers = %d, want 0", len(sc.keyManagers))
	}
	if len(sc.primitiveConstructors) != 1 {
		t.Errorf("Number of registered primitive constructors = %d, want 1", len(sc.primitiveConstructors))
	}
	if _, ok := sc.primitiveConstructors[reflect.TypeFor[aesgcm.Key]()]; !ok {
		t.Errorf("RegisterKeyManager() registered wrong type, want %q", reflect.TypeFor[aesgcm.Key]())
	}
}

func TestRegisterKeyManagerFailsIfConfigFails(t *testing.T) {
	sc := &alwaysFailingStubConfig{}
	if err := aesgcm.RegisterKeyManager(sc, internalapi.Token{}); err == nil {
		t.Errorf("RegisterKeyManager() err = nil, want error")
	}
}

func TestRegisterPrimitiveConstructorFailsIfConfigFails(t *testing.T) {
	sc := &alwaysFailingStubConfig{}
	if err := aesgcm.RegisterPrimitiveConstructor(sc, internalapi.Token{}); err == nil {
		t.Errorf("RegisterPrimitiveConstructor() err = nil, want error")
	}
}
