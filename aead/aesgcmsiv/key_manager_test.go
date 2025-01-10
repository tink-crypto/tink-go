// Copyright 2018 Google LLC
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
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	aeadtestutil "github.com/tink-crypto/tink-go/v2/aead/internal/testutil"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	gcmsivpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var aesGCMSIVKeySizes = []uint32{16, 32}

func TestKeyManagerGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		t.Run(fmt.Sprintf("keySize=%d", keySize), func(t *testing.T) {
			key := testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, uint32(keySize))
			serializedKey, err := proto.Marshal(key)
			if err != nil {
				t.Fatalf("proto.Marshal(data=%+v): Failed to serialize key for keySize=%d, skipping test iteration; err=%v", key, keySize, err)
			}
			p, err := keyManager.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("Primitive(serializedKey=%v): Unexpected error creating AES-GCM-SIV primitive with keySize=%d, skipping test iteration; err=%v", serializedKey, keySize, err)
			}
			aesGCMSIV, ok := p.(tink.AEAD)
			if !ok {
				t.Fatalf("Primitive(serializedKey=%v): Primitive is not a tink.AEAD", serializedKey)
			}

			subtleAESGCMSIV, err := subtle.NewAESGCMSIV(key.GetKeyValue())
			if err != nil {
				t.Fatalf("subtle.NewAESGCMSIV(key.GetKeyValue()) err = %v, want nil", err)
			}
			if err := aeadtestutil.EncryptDecrypt(aesGCMSIV, subtleAESGCMSIV); err != nil {
				t.Errorf("aeadtestutil.EncryptDecrypt(aesGCMSIV, subtleAESGCMSIV) err = %v, want nil", err)
			}
			if err := aeadtestutil.EncryptDecrypt(subtleAESGCMSIV, aesGCMSIV); err != nil {
				t.Errorf("aeadtestutil.EncryptDecrypt(subtleAESGCMSIV, aesGCMSIV) err = %v, want nil", err)
			}
		})
	}
}

func TestKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	// invalid AESGCMSIVKey
	testKeys := genInvalidAESGCMSIVKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Errorf("Primitive(serializedKey=%v): Key %d, got err = nil, want err != nil.", serializedKey, i)
		}
	}
	// nil
	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("Primitive(serializedKey=nil): Key nil, got err = nil, want err != nil.")
	}
	// empty array
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("Primitive(serializedKey=[]): Key empty, got err = nil, want err != nil.")
	}
}

func TestKeyManagerNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	format := testutil.NewAESGCMSIVKeyFormat(32)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("proto.Marshal(data=%+v): Failed to serialize key format; err=%v", format, err)
	}
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Failed to create new key on iteration %d; err=%v", serializedFormat, i, err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key on iteration %d; err=%v", key, i, err)
		}
		keys[string(serializedKey)] = true

		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("NewKeyData(serializedFormat=%v): Failed to create new key data on iteration %d; err=%v", serializedFormat, i, err)
		}
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("TestKeyManagerNewKeyMultipleTimes(): Got %d unique keys, want %d.", len(keys), nTest*2)
	}
}

func TestKeyManagerNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		format := testutil.NewAESGCMSIVKeyFormat(uint32(keySize))
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key format for keySize=%d, skipping remainder of test iteration; err=%v", format, keySize, err)
			continue
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Unexpected error for keySize=%d, skipping remainder of test iteration; err=%v", serializedFormat, keySize, err)
			continue
		}
		key := m.(*gcmsivpb.AesGcmSivKey)
		if err := validateAESGCMSIVKey(key, format); err != nil {
			t.Errorf("validateAESGCMSIVKey(key=%v): Error trying to validate key for keySize=%d; err=%v", key, keySize, err)
		}
	}
}

func TestKeyManagerNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	// bad format
	badFormats := genInvalidAESGCMSIVKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("NewKey(serializedKeyFormat=%v): Key %d, got err = nil, want err != nil", serializedFormat, i)
		}
	}
	// nil
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Errorf("NewKey(serializedKeyFormat=nil): Key nil, got err = nil, want err != nil")
	}
	// empty array
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Errorf("NewKey(serializedKeyFormat=[]): Key empty, got err = nil, want err != nil")
	}
}

func TestKeyManagerNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	for _, keySize := range aesGCMSIVKeySizes {
		format := testutil.NewAESGCMSIVKeyFormat(uint32(keySize))
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Failed to serialize key format for keySize=%d, skipping remainder of test iteration; err=%v", format, keySize, err)
			continue
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Failed to create keyData for keySize=%d, skipping remainder of test iteration; err=%v", serializedFormat, keySize, err)
			continue
		}
		if keyData.TypeUrl != testutil.AESGCMSIVTypeURL {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Incorrect type url for keySize=%d, got %s, want %s.", serializedFormat, keySize, keyData.TypeUrl, testutil.AESGCMSIVTypeURL)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Incorrect key material type for keySize=%d, got %d, want %d.", serializedFormat, keySize, keyData.KeyMaterialType, tinkpb.KeyData_SYMMETRIC)
		}
		key := new(gcmsivpb.AesGcmSivKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("proto.Unmarshal(data=%v): Failed to load keyData into key for keySize=%d, skipping remainder of test iteration; err=%v", keyData.Value, keySize, err)
			continue
		}
		if err := validateAESGCMSIVKey(key, format); err != nil {
			t.Errorf("validateAESGCMSIVKey(key=%v): Failed to validate key for keySize=%d; err=%v", key, keySize, err)
		}
		p, err := registry.PrimitiveFromKeyData(keyData)
		if err != nil {
			t.Errorf("registry.PrimitiveFromKeyData(keyData) err = %v, want nil", err)
		}
		aesGCMSIV, ok := p.(tink.AEAD)
		if !ok {
			t.Error("registry.PrimitiveFromKeyData(keyData) not a tink.AEAD")
			continue
		}

		subtleAESGCMSIV, err := subtle.NewAESGCMSIV(key.GetKeyValue())
		if err != nil {
			t.Errorf("subtle.NewAESGCMSIV(key.GetKeyValue()) err = %v, want nil", err)
			continue
		}
		if err := aeadtestutil.EncryptDecrypt(aesGCMSIV, subtleAESGCMSIV); err != nil {
			t.Errorf("aeadtestutil.EncryptDecrypt(aesGCMSIV, subtleAESGCMSIV) err = %v, want nil", err)
		}
		if err := aeadtestutil.EncryptDecrypt(subtleAESGCMSIV, aesGCMSIV); err != nil {
			t.Errorf("aeadtestutil.EncryptDecrypt(subtleAESGCMSIV, aesGCMSIV) err = %v, want nil", err)
		}
	}
}

func TestKeyManagerNewKeyDataWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	badFormats := genInvalidAESGCMSIVKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("proto.Marshal(data=%+v): Key %d, failed to serialize key format, skipping remainder of test iteration; err=%v", badFormats[i], i, err)
			continue
		}
		if _, err := keyManager.NewKeyData(serializedFormat); err == nil {
			t.Errorf("NewKeyData(serializedKeyFormat=%v): Key %d, got err = nil, want err != nil.", serializedFormat, i)
		}
	}
	// nil input
	if _, err := keyManager.NewKeyData(nil); err == nil {
		t.Errorf("NewKeyData(serializedKeyFormat=nil): Key nil, got err = nil, want err != nil")
	}
	// empty input
	if _, err := keyManager.NewKeyData([]byte{}); err == nil {
		t.Errorf("NewKeyData(serializedKeyFormat=[]): Key empty, got err = nil, want err != nil")
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	if !keyManager.DoesSupport(testutil.AESGCMSIVTypeURL) {
		t.Errorf("DoesSupport(typeURL=%s): got false, want true", testutil.AESGCMSIVTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("DoesSupport(typeURL=\"some bad type\"): got true, want false")
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMSIVTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(typeURL=%s): Cannot obtain AES-GCM-SIV key manager; err=%v", testutil.AESGCMSIVTypeURL, err)
	}
	if keyManager.TypeURL() != testutil.AESGCMSIVTypeURL {
		t.Errorf("GetKeyManager(%s): Incorrect key type for key manager, got %s, want %s.", testutil.AESGCMSIVTypeURL, keyManager.TypeURL(), testutil.AESGCMSIVTypeURL)
	}
}

func genInvalidAESGCMSIVKeys() []proto.Message {
	return []proto.Message{
		// not a AESGCMSIVKey
		testutil.NewAESGCMSIVKeyFormat(32),
		// bad key size
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 17),
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 25),
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 33),
		// bad version
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion+1, 16),
	}
}

func genInvalidAESGCMSIVKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESGCMSIVKeyFormat
		testutil.NewAESGCMSIVKey(testutil.AESGCMSIVKeyVersion, 16),
		// invalid key size
		testutil.NewAESGCMSIVKeyFormat(uint32(15)),
		testutil.NewAESGCMSIVKeyFormat(uint32(23)),
		testutil.NewAESGCMSIVKeyFormat(uint32(31)),
	}
}

func validateAESGCMSIVKey(key *gcmsivpb.AesGcmSivKey, format *gcmsivpb.AesGcmSivKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size, got %d, want %d", uint32(len(key.KeyValue)), format.KeySize)
	}
	if key.Version != testutil.AESGCMSIVKeyVersion {
		return fmt.Errorf("incorrect key version, got %d, want %d", key.Version, testutil.AESGCMSIVKeyVersion)
	}
	// Try to encrypt and decrypt random data.
	p, err := subtle.NewAESGCMSIV(key.KeyValue)
	if err != nil {
		return fmt.Errorf("subtle.NewAESGCMSIV(key=%v): Invalid key; err=%v", key.KeyValue, err)
	}
	return aeadtestutil.EncryptDecrypt(p, p)
}
