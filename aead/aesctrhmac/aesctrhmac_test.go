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

package aesctrhmac_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

func TestGetKeyFromHandle(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate()) err = %v, want nil", err)
	}
	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*aesctrhmac.Key)
	if !ok {
		t.Fatalf("entry.Key() type = %T, want *aesctrhmac.Key", entry.Key())
	}
	aesKeySizeInBytes := 16
	hmacKeySizeInBytes := 32
	opts := aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  aesKeySizeInBytes,
		HMACKeySizeInBytes: hmacKeySizeInBytes,
		IVSizeInBytes:      16,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantTink,
	}
	wantParams, err := aesctrhmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", opts, err)
	}
	if diff := cmp.Diff(key.Parameters(), wantParams); diff != "" {
		t.Errorf("key.Parameters() diff (-want +got):\n%s", diff)
	}
	if _, hasIDRequirement := key.IDRequirement(); !hasIDRequirement {
		t.Errorf("expected ID requirement, got none")
	}
	// Validate key length.
	aesKeyBytes := key.AESKeyBytes()
	if aesKeyBytes.Len() != aesKeySizeInBytes {
		t.Errorf("aesKeyBytes.Len() = %v, want %v", aesKeyBytes.Len(), aesKeySizeInBytes)
	}
	hmacKeyBytes := key.HMACKeyBytes()
	if hmacKeyBytes.Len() != hmacKeySizeInBytes {
		t.Errorf("hmacKeyBytes.Len() = %v, want %v", hmacKeyBytes.Len(), hmacKeySizeInBytes)
	}
}

func TestCreateKeysetHandleFromKey(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate()) err = %v, want nil", err)
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
	key, ok := entry.Key().(*aesctrhmac.Key)
	if !ok {
		t.Errorf("entry.Key() is not *aesctrhmac.Key")
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
	opts := aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA512,
		Variant:            aesctrhmac.VariantTink,
	}
	params, err := aesctrhmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", opts, err)
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

	err := aesctrhmac.RegisterKeyManager(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("aesctrhmac.RegisterKeyManager() err = %v, want nil", err)
	}

	if len(sc.PrimitiveConstructors) != 0 {
		t.Errorf("Number of registered primitive constructors = %d, want 0", len(sc.PrimitiveConstructors))
	}
	if len(sc.KeyManagers) != 1 {
		t.Errorf("Number of registered key types = %d, want 1", len(sc.KeyManagers))
	}
	if _, ok := sc.KeyManagers[testutil.AESCTRHMACAEADTypeURL]; !ok {
		t.Errorf("aesctrhmac.RegisterKeyManager() registered wrong type URL, want \"%v\"", testutil.AESCTRHMACAEADTypeURL)
	}
}

func TestRegisterPrimitiveConstructor(t *testing.T) {
	sc := stubconfig.NewStubConfig()
	if len(sc.KeyManagers) != 0 {
		t.Fatalf("Initial number of registered key types = %d, want 0", len(sc.KeyManagers))
	}

	err := aesctrhmac.RegisterPrimitiveConstructor(sc, internalapi.Token{})
	if err != nil {
		t.Fatalf("aesctrhmac.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	if len(sc.PrimitiveConstructors) != 1 {
		t.Errorf("Number of registered primitive constructors = %d, want 0", len(sc.PrimitiveConstructors))
	}
	if len(sc.KeyManagers) != 0 {
		t.Errorf("Number of registered key types = %d, want 1", len(sc.KeyManagers))
	}
	kt := reflect.TypeFor[*aesctrhmac.Key]()
	if _, ok := sc.PrimitiveConstructors[kt]; !ok {
		t.Errorf("aesctrhmac.RegisterPrimitiveConstructor() registered wrong key type, want \"%v\"", kt)
	}
}
