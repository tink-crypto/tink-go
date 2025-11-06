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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
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

func TestRegisterPrimitiveConstructor(t *testing.T) {
	cb := config.NewBuilder()
	err := aesctrhmac.RegisterPrimitiveConstructor(cb, internalapi.Token{})
	if err != nil {
		t.Fatalf("aesctrhmac.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	c := cb.Build()

	opts := aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 32,
		IVSizeInBytes:      16,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantTink,
	}
	params, err := aesctrhmac.NewParameters(opts)
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters(%v) err = %v, want nil", opts, err)
	}
	key, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
		AESKeyBytes:   secretdata.NewBytesFromData(make([]byte, 16), insecuresecretdataaccess.Token{}),
		HMACKeyBytes:  secretdata.NewBytesFromData(make([]byte, 32), insecuresecretdataaccess.Token{}),
		IDRequirement: 0x1234,
		Parameters:    params,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}
	if _, err := c.PrimitiveFromKey(key, internalapi.Token{}); err != nil {
		t.Errorf("c.PrimitiveFromKey(key) err = %v, want nil", err)
	}
}

func TestGetKeyManager(t *testing.T) {
	// From https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.
	//
	// We use CTR but the RFC uses CBC mode, so it's not possible to compare
	// plaintexts. However, the tests are still valuable to ensure that we
	// correctly compute HMAC over ciphertext and associatedData.
	macKeyBytes := mustDecodeHex(t, "000102030405060708090a0b0c0d0e0f")
	aesKeyBytes := mustDecodeHex(t, "101112131415161718191a1b1c1d1e1f")
	ciphertext := mustDecodeHex(t, ""+
		"1af38c2dc2b96ffdd86694092341bc04"+
		"c80edfa32ddf39d5ef00c0b468834279"+
		"a2e46a1b8049f792f76bfe54b903a9c9"+
		"a94ac9b47ad2655c5f10f9aef71427e2"+
		"fc6f9b3f399a221489f16362c7032336"+
		"09d45ac69864e3321cf82935ac4096c8"+
		"6e133314c54019e8ca7980dfa4b9cf1b"+
		"384c486f3a54c51078158ee5d79de59f"+
		"bd34d848b3d69550a67646344427ade5"+
		"4b8851ffb598f7f80074b9473c82e2db"+
		"652c3fa36b0a7c5b3219fab3a30bc1c4")
	associatedData := mustDecodeHex(t, ""+
		"546865207365636f6e64207072696e63"+
		"69706c65206f66204175677573746520"+
		"4b6572636b686f666673")

	params, err := aesctrhmac.NewParameters(aesctrhmac.ParametersOpts{
		AESKeySizeInBytes:  16,
		HMACKeySizeInBytes: 16,
		IVSizeInBytes:      16,
		TagSizeInBytes:     16,
		HashType:           aesctrhmac.SHA256,
		Variant:            aesctrhmac.VariantTink,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewParameters() err = %v, want nil", err)
	}
	key, err := aesctrhmac.NewKey(aesctrhmac.KeyOpts{
		AESKeyBytes:   secretdata.NewBytesFromData(aesKeyBytes, insecuresecretdataaccess.Token{}),
		HMACKeyBytes:  secretdata.NewBytesFromData(macKeyBytes, insecuresecretdataaccess.Token{}),
		IDRequirement: 0x1234,
		Parameters:    params,
	})
	if err != nil {
		t.Fatalf("aesctrhmac.NewKey() err = %v, want nil", err)
	}

	keySerialization, err := protoserialization.SerializeKey(key)
	if err != nil {
		t.Fatalf("protoserialization.SerializeKey() err = %v, want nil", err)
	}

	km, err := registry.GetKeyManager(testutil.AESCTRHMACAEADTypeURL)
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

	if _, err := aead.Decrypt(ciphertext, associatedData); err != nil {
		t.Fatalf("Decrypt() err = %v, want nil", err)
	}
}
