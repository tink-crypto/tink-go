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

package aesgcmsiv_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcmsiv"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestGetKeyFromHandle(t *testing.T) {
	keysetHandle, err := keyset.NewHandle(aead.AES128GCMSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES128GCMSIVKeyTemplate()) err = %v, want nil", err)
	}
	entry, err := keysetHandle.Entry(0)
	if err != nil {
		t.Fatalf("keysetHandle.Entry(0) err = %v, want nil", err)
	}
	key, ok := entry.Key().(*aesgcmsiv.Key)
	if !ok {
		t.Fatalf("entry.Key() is not an *Key")
	}
	keySize := 16
	expectedParameters, err := aesgcmsiv.NewParameters(keySize, aesgcmsiv.VariantTink)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", keySize, aesgcmsiv.VariantTink, err)
	}
	if !key.Parameters().Equal(expectedParameters) {
		t.Errorf("key.Parameters().Equal(expectedParameters) = false, want true")
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
	keysetHandle, err := keyset.NewHandle(aead.AES256GCMSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMSIVKeyTemplate()) err = %v, want nil", err)
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
	key, ok := entry.Key().(*aesgcmsiv.Key)
	if !ok {
		t.Fatalf("entry.Key() is not *aesgcmsiv.Key")
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
	params, err := aesgcmsiv.NewParameters(32, aesgcmsiv.VariantTink)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", 32, aesgcmsiv.VariantTink, err)
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

func TestRegisterPrimitiveConstructor(t *testing.T) {
	cb := config.NewBuilder()
	err := aesgcmsiv.RegisterPrimitiveConstructor(cb, internalapi.Token{})
	if err != nil {
		t.Fatalf("aesgcmsiv.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	c := cb.Build()

	params, err := aesgcmsiv.NewParameters(32, aesgcmsiv.VariantTink)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters(%v, %v) err = %v, want nil", 32, aesgcmsiv.VariantTink, err)
	}
	key, err := aesgcmsiv.NewKey(secretdata.NewBytesFromData([]byte("00000000000000000000000000000000"), testonlyinsecuresecretdataaccess.Token()), 0x1234, params)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewKey() err = %v, want nil", err)
	}
	if _, err := c.PrimitiveFromKey(key, internalapi.Token{}); err != nil {
		t.Errorf("c.PrimitiveFromKey(key) err = %v, want nil", err)
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

func TestGetKeyManager(t *testing.T) {
	keyBytes := secretdata.NewBytesFromData(mustDecodeHex(t, "01000000000000000000000000000000"), testonlyinsecuresecretdataaccess.Token())
	wantMessage := mustDecodeHex(t, "01000000000000000000000000000000")
	ciphertext := mustDecodeHex(t, "030000000000000000000000743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4")
	params, err := aesgcmsiv.NewParameters(keyBytes.Len(), aesgcmsiv.VariantTink)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewParameters() err = %v, want nil", err)
	}
	key, err := aesgcmsiv.NewKey(keyBytes, 0x1234, params)
	if err != nil {
		t.Fatalf("aesgcmsiv.NewKey() err = %v, want nil", err)
	}

	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
	}

	km, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
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
	decrypted, err := aead.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(decrypted, wantMessage) {
		t.Errorf("Decrypt() = %v, want %v", decrypted, wantMessage)
	}
}
