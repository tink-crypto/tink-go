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

package chacha20poly1305_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestGetKeyFromHandle(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate()) err = %v, want nil", err)
	}
	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*chacha20poly1305.Key)
	if !ok {
		t.Errorf("entry.Key() is not a *chacha20poly1305.Key")
	}
	expectedParameters, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", chacha20poly1305.VariantTink, err)
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
	keysetHandle, err := keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate()) err = %v, want nil", err)
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
	key, ok := entry.Key().(*chacha20poly1305.Key)
	if !ok {
		t.Errorf("entry.Key() is not *chacha20poly1305.Key")
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
	params, err := chacha20poly1305.NewParameters(chacha20poly1305.VariantTink)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters(%v) err = %v, want nil", chacha20poly1305.VariantTink, err)
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
