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
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func TestGetAESGCMKeyFromHandle(t *testing.T) {
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

func TestCreateKeysetHandleFromAESGCMKey(t *testing.T) {
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
