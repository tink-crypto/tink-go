// Copyright 2020 Google LLC
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

package aesgcmhkdf_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/streamingaead/aesgcmhkdf"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	gcmhkdfpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_hkdf_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		key := testutil.NewAESGCMHKDFKey(testutil.AESGCMHKDFKeyVersion, keySize, keySize, commonpb.HashType_SHA256, 4096)
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		p, err := keyManager.Primitive(serializedKey)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if err := validatePrimitive(p, key); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestGetPrimitiveWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}

	testKeys := genInvalidAESGCMHKDFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		if _, err := keyManager.Primitive(serializedKey); err == nil {
			t.Fatalf("expect an error in test case %d", i)
		}
	}

	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
	keyNilParams := testutil.NewAESGCMHKDFKey(testutil.AESGCMHKDFKeyVersion, 32, 32, commonpb.HashType_SHA256, 4096)
	keyNilParams.Params = nil
	serializedKeyNilParams, err := proto.Marshal(keyNilParams)
	if err != nil {
		t.Fatalf("proto.Marshal(keyNilParams) err = %v, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedKeyNilParams); err == nil {
		t.Errorf("keyManager.Primitive(serializedKeyNilParams) err = nil, want non-nil")
	}
}

func TestNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	format := testutil.NewAESGCMHKDFKeyFormat(32, 32, commonpb.HashType_SHA256, 4096)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("failed to marshal key: %s", err)
	}
	keys := make(map[string]struct{})
	n := 26
	for i := 0; i < n; i++ {
		key, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Fatalf("keyManager.NewKey() err = %q, want nil", err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		keys[string(serializedKey)] = struct{}{}

		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("keyManager.NewKeyData() err = %q, want nil", err)
		}
		serializedKey = keyData.Value
		keys[string(serializedKey)] = struct{}{}
	}
	if len(keys) != n*2 {
		t.Errorf("key is repeated")
	}
}

func TestNewKeyBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		format := testutil.NewAESGCMHKDFKeyFormat(
			keySize,
			keySize,
			commonpb.HashType_SHA256,
			4096,
		)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		key := m.(*gcmhkdfpb.AesGcmHkdfStreamingKey)
		if err := validateAESGCMHKDFKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	// bad format
	badFormats := genInvalidAESGCMHKDFKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Fatalf("expect an error in test case %d", i)
		}
	}
	// nil
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Fatalf("expect an error when input is nil")
	}
	// empty array
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Fatalf("expect an error when input is empty")
	}
	// params field is unset
	formatNilParams := testutil.NewAESGCMHKDFKeyFormat(32, 32, commonpb.HashType_SHA256, 4096)
	formatNilParams.Params = nil
	serializedFormatNilParams, err := proto.Marshal(formatNilParams)
	if err != nil {
		t.Fatalf("proto.Marshal(formatNilParams) err = %v, want nil", err)
	}
	if _, err := keyManager.NewKey(serializedFormatNilParams); err == nil {
		t.Errorf("keyManager.NewKey(serializedFormatNilParams) err = nil, want non-nil")
	}
}

func TestNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		format := testutil.NewAESGCMHKDFKeyFormat(
			keySize,
			keySize,
			commonpb.HashType_SHA256,
			4096,
		)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Fatalf("failed to marshal key: %s", err)
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if keyData.TypeUrl != testutil.AESGCMHKDFTypeURL {
			t.Fatalf("incorrect type url")
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Fatalf("incorrect key material type")
		}
		key := new(gcmhkdfpb.AesGcmHkdfStreamingKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Fatalf("incorrect key value")
		}
		if err := validateAESGCMHKDFKey(key, format); err != nil {
			t.Fatalf("%s", err)
		}
		p, err := registry.PrimitiveFromKeyData(keyData)
		if err != nil {
			t.Fatalf("registry.PrimitiveFromKeyData(keyData) err = %v, want nil", err)
		}
		_, ok := p.(*subtle.AESGCMHKDF)
		if !ok {
			t.Error("registry.PrimitiveFromKeyData(keyData) did not return a AESGCMHKDF primitive")
		}
	}
}

func TestNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	badFormats := genInvalidAESGCMHKDFKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.NewKeyData([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestDoesSupport(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	if !keyManager.DoesSupport(testutil.AESGCMHKDFTypeURL) {
		t.Fatalf("AESGCMHKDFKeyManager must support %s", testutil.AESGCMHKDFTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("AESGCMHKDFKeyManager must support only %s", testutil.AESGCMHKDFTypeURL)
	}
}

func TestTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESGCMHKDFTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-GCM-HKDF key manager: %s", err)
	}
	if keyManager.TypeURL() != testutil.AESGCMHKDFTypeURL {
		t.Errorf("incorrect key type")
	}
}

func genInvalidAESGCMHKDFKeys() []proto.Message {
	return []proto.Message{
		// not a AESGCMHKDFKey
		testutil.NewAESGCMHKDFKeyFormat(32, 32, commonpb.HashType_SHA256, 4096),
		// bad key size
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 17, 16, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 16, 17, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 33, 33, commonpb.HashType_SHA256, 4096),
		// bad version
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion+1, 16, 16, commonpb.HashType_SHA256, 4096),
	}
}

func genInvalidAESGCMHKDFKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESGCMKeyFormat
		testutil.NewAESGCMHKDFKey(testutil.AESGCMKeyVersion, 16, 16, commonpb.HashType_SHA256, 16),
		// invalid key size
		testutil.NewAESGCMHKDFKeyFormat(17, 16, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKeyFormat(16, 17, commonpb.HashType_SHA256, 4096),
		testutil.NewAESGCMHKDFKeyFormat(33, 33, commonpb.HashType_SHA256, 4096),
	}
}

func validateAESGCMHKDFKey(key *gcmhkdfpb.AesGcmHkdfStreamingKey, format *gcmhkdfpb.AesGcmHkdfStreamingKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size")
	}
	if key.Version != testutil.AESGCMKeyVersion {
		return fmt.Errorf("incorrect key version")
	}
	if key.Params.CiphertextSegmentSize != format.Params.CiphertextSegmentSize {
		return fmt.Errorf("incorrect ciphertext segment size")
	}
	if key.Params.DerivedKeySize != format.Params.DerivedKeySize {
		return fmt.Errorf("incorrect derived key size")
	}
	if key.Params.HkdfHashType != format.Params.HkdfHashType {
		return fmt.Errorf("incorrect HKDF hash type")
	}
	// try to encrypt and decrypt
	p, err := subtle.NewAESGCMHKDF(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		int(key.Params.CiphertextSegmentSize),
		0,
	)
	if err != nil {
		return fmt.Errorf("invalid key")
	}
	return validatePrimitive(p, key)
}

func validatePrimitive(p any, key *gcmhkdfpb.AesGcmHkdfStreamingKey) error {
	cipher := p.(*subtle.AESGCMHKDF)
	return encryptDecrypt(cipher, cipher, 32, 32)
}

func encryptDecrypt(encryptCipher, decryptCipher tink.StreamingAEAD, ptSize, aadSize int) error {
	pt := random.GetRandomBytes(uint32(ptSize))
	aad := random.GetRandomBytes(uint32(aadSize))

	buf := &bytes.Buffer{}
	w, err := encryptCipher.NewEncryptingWriter(buf, aad)
	if err != nil {
		return fmt.Errorf("cannot create encrypt writer: %v", err)
	}
	if _, err := w.Write(pt); err != nil {
		return fmt.Errorf("error writing data: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("error closing writer: %v", err)
	}

	r, err := decryptCipher.NewDecryptingReader(buf, aad)
	if err != nil {
		return fmt.Errorf("cannot create decrypt reader: %v", err)
	}
	ptGot := make([]byte, len(pt)+1)
	n, err := io.ReadFull(r, ptGot)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("decryption failed: %v", err)
	}
	ptGot = ptGot[:n]
	if !bytes.Equal(pt, ptGot) {
		return fmt.Errorf("decryption failed")
	}
	return nil
}
