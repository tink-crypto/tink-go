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

package xaesgcm_test

import (
	"bytes"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/xaesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestCreateKeysetHandleFromKeysetKey(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.XAES256GCM192BitNonceKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.XAES256GCM192BitNonceKeyTemplate()) err = %v, want nil", err)
	}
	aeadPrimitive, err := aead.New(keysetHandle)
	if err != nil {
		t.Fatalf("aead.New(keysetHandle) err = %v, want nil", err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := aeadPrimitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
	}

	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*xaesgcm.Key)
	if !ok {
		t.Fatalf("entry.Key() is not *xaesgcm.Key")
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
	decrypt, err := newAEAD.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("decrypt.New(otherAEADPrimitivce, %v, %v) err = %v, want nil", ciphertext, associatedData, err)
	}
	if !bytes.Equal(decrypt, plaintext) {
		t.Errorf("decrypt = %v, want %v", decrypt, plaintext)
	}
}

func TestCreateKeysetHandleFromKey(t *testing.T) {
	params, err := xaesgcm.NewParameters(xaesgcm.VariantTink, 12)
	if err != nil {
		t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", xaesgcm.VariantTink, 12, err)
	}
	key, err := xaesgcm.NewKey(secretdata.NewBytesFromData([]byte("01010101010101010101010101010101"), insecuresecretdataaccess.Token{}), 0x11223344, params)
	if err != nil {
		t.Fatalf("xaesgcm.NewKey(%x, %v, %v) err = %v, want nil", key.KeyBytes().Data(insecuresecretdataaccess.Token{}), 0x11223344, params, err)
	}
	a1, err := xaesgcm.NewAEAD(key, internalapi.Token{})
	if err != nil {
		t.Fatalf("xaesgcm.NewAEAD(%v, %v) err = %v, want nil", key, internalapi.Token{}, err)
	}
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := a1.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a1.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}

	// Create a new keyset handle with the same key and decrypt the ciphertext.
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
	a2, err := aead.New(newHandle)
	if err != nil {
		t.Fatalf("aead.New(newHandle) err = %v, want nil", err)
	}
	decrypt, err := a2.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a2.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(decrypt, plaintext) {
		t.Errorf("decrypt = %v, want %v", decrypt, plaintext)
	}
}

func TestCreateKeysetHandleFromParameters(t *testing.T) {
	params, err := xaesgcm.NewParameters(xaesgcm.VariantTink, 12)
	if err != nil {
		t.Fatalf("xaesgcm.NewParameters(%v, %v) err = %v, want nil", xaesgcm.VariantTink, 12, err)
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
	associatedData := []byte("associatedData")
	ciphertext, err := aeadPrimitive.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Encrypt(%v, %v) err = %v, want nil", plaintext, associatedData, err)
	}
	decrypted, err := aeadPrimitive.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aeadPrimitive.Decrypt(%v, %v) err = %v, want nil", ciphertext, associatedData, err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %v, want %v", decrypted, plaintext)
	}
}