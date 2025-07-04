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

package xchacha20poly1305_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/xchacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestGetKeyFromHandle(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate()) err = %v, want nil", err)
	}
	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*xchacha20poly1305.Key)
	if !ok {
		t.Errorf("entry.Key() is not a *xchacha20poly1305.Key")
	}
	expectedParameters, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", xchacha20poly1305.VariantTink, err)
	}
	if !key.Parameters().Equal(expectedParameters) {
		t.Errorf("key.Parameters().Equal(expectedParameters) = false, want true")
	}
	if _, hasIDRequirement := key.IDRequirement(); !hasIDRequirement {
		t.Errorf("expected ID requirement, got none")
	}
	keyBytes := key.KeyBytes()
	if keyBytes.Len() != 32 {
		t.Errorf("keyBytes.Len() = %v, want %v", keyBytes.Len(), 32)
	}
}

func TestCreateKeysetHandleFromKey(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate()) err = %v, want nil", err)
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
	key, ok := entry.Key().(*xchacha20poly1305.Key)
	if !ok {
		t.Errorf("entry.Key() is not *xchacha20poly1305.Key")
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
	params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters(%v) err = %v, want nil", xchacha20poly1305.VariantTink, err)
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

func TestRegisterKeyManager(t *testing.T) {
	sc := stubconfig.NewStubConfig()
	if len(sc.KeyManagers) != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", len(sc.KeyManagers))
	}

	err := xchacha20poly1305.RegisterKeyManager(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("xchacha20poly1305.RegisterKeyManager() err = %v, want nil", err)
	}

	if len(sc.PrimitiveConstructors) != 0 {
		t.Errorf("Number of registered primitive constructors = %d, want 0", len(sc.PrimitiveConstructors))
	}
	if len(sc.KeyManagers) != 1 {
		t.Errorf("Number of registered key types = %d, want 1", len(sc.KeyManagers))
	}
	if _, ok := sc.KeyManagers[testutil.XChaCha20Poly1305TypeURL]; !ok {
		t.Errorf("xchacha20poly1305.RegisterKeyManager() registered wrong type URL, want \"%v\"", testutil.XChaCha20Poly1305TypeURL)
	}
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	sc := stubconfig.NewStubConfig()
	if len(sc.KeyManagers) != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", len(sc.KeyManagers))
	}

	err := xchacha20poly1305.RegisterPrimitiveConstructor(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("xchacha20poly1305.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	if len(sc.PrimitiveConstructors) != 1 {
		t.Errorf("Number of registered primitive constructors = %d, want 0", len(sc.PrimitiveConstructors))
	}
	if len(sc.KeyManagers) != 0 {
		t.Errorf("Number of registered key types = %d, want 1", len(sc.KeyManagers))
	}
	kt := reflect.TypeFor[*xchacha20poly1305.Key]()
	if _, ok := sc.PrimitiveConstructors[kt]; !ok {
		t.Errorf("xchacha20poly1305.RegisterPrimitiveConstructor() registered wrong key type, want \"%v\"", kt)
	}
}

func TestGetKeyManager(t *testing.T) {
	// https://github.com/C2SP/wycheproof/blob/b063b4aedae951c69df014cd25fa6d69ae9e8cb9/testvectors/xchacha20_poly1305_test.json#L21
	keyBytes := secretdata.NewBytesFromData(mustDecodeHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"), insecuresecretdataaccess.Token{})
	wantMessage := mustDecodeHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")

	iv := "404142434445464748494a4b4c4d4e4f5051525354555657"
	ct := "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
	tag := "c0875924c1c7987947deafd8780acf49"
	ciphertext := mustDecodeHex(t, iv+ct+tag)
	aad := mustDecodeHex(t, "50515253c0c1c2c3c4c5c6c7")
	params, err := xchacha20poly1305.NewParameters(xchacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewParameters() err = %v, want nil", err)
	}
	key, err := xchacha20poly1305.NewKey(keyBytes, 0x1234, params)
	if err != nil {
		t.Fatalf("xchacha20poly1305.NewKey() err = %v, want nil", err)
	}

	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
	}

	km, err := registry.GetKeyManager(testutil.XChaCha20Poly1305TypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %v, want nil", err)
	}
	km.Primitive(keySerialization.KeyData().GetValue())
	// It is expected to ignore the output prefix.
	primitive, err := km.Primitive(keySerialization.KeyData().GetValue())
	if err != nil {
		t.Fatalf("GetPrimitive() err = %v, want nil", err)
	}
	aead, ok := primitive.(tink.AEAD)
	if !ok {
		t.Errorf("GetPrimitive() = %T, want tink.AEAD", primitive)
	}
	decrypted, err := aead.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(decrypted, wantMessage) {
		t.Errorf("Decrypt() = %v, want %v", decrypted, wantMessage)
	}
}
