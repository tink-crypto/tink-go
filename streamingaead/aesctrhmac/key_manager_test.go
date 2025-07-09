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

package aesctrhmac_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/streamingaead/aesctrhmac"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	ctrhmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_streaming_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestGetPrimitiveBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		key := testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
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
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Fatalf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}

	for _, tc := range []struct {
		name     string
		protoKey proto.Message
	}{
		{
			name:     "not a AESCTRHMACKey",
			protoKey: testutil.NewAESCTRHMACKeyFormat(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096),
		},
		{
			name:     "bad key size",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 17, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
		},
		{
			name:     "bad derived key size",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 17, commonpb.HashType_SHA256, 16, 4096),
		},
		{
			name:     "bad keys size",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 33, commonpb.HashType_SHA256, 33, commonpb.HashType_SHA256, 16, 4096),
		},
		{
			name:     "bad version",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion+1, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
		},
		{
			name:     "bad ciphertext_segment_size",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 2147483648)},
		{
			name:     "bad hmac params hash type",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA224, 16, 4096)},
		{
			name:     "bad hmac params hash type",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA384, 16, 4096)},
		{
			name:     "bad hkdf hash type",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA224, 16, commonpb.HashType_SHA256, 16, 4096)},
		{
			name:     "bad hkdf hash type",
			protoKey: testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA384, 16, commonpb.HashType_SHA256, 16, 4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.protoKey)
			if err != nil {
				t.Fatalf("proto.Marshal(tc.protoKey) err = %v, want nil", err)
			}
			if _, err := keyManager.Primitive(serializedKey); err == nil {
				t.Errorf("keyManager.Primitive(serializedKey) err = nil, want non-nil")
			}
		})
	}

	if _, err := keyManager.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	if _, err := keyManager.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}

	keyNilParams := testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096)
	keyNilParams.Params = nil
	serializedKeyNilParams, err := proto.Marshal(keyNilParams)
	if err != nil {
		t.Errorf("proto.Marshal(keyNilParams) err = %v, want nil", err)
	}
	if _, err := keyManager.Primitive(serializedKeyNilParams); err == nil {
		t.Errorf("keyManager.Primitive(serializedKeyNilParams) err = nil, want non-nil")
	}
}

func TestNewKeyMultipleTimes(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	format := testutil.NewAESCTRHMACKeyFormat(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096)
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Errorf("failed to marshal key: %s", err)
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
			t.Errorf("failed to marshal key: %s", err)
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
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		format := testutil.NewAESCTRHMACKeyFormat(keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		m, err := keyManager.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		key := m.(*ctrhmacpb.AesCtrHmacStreamingKey)
		if err := validateAESCTRHMACKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestNewKeyWithInvalidInput(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	// bad format
	badFormats := genInvalidAESCTRHMACKeyFormats()
	for i := 0; i < len(badFormats); i++ {
		serializedFormat, err := proto.Marshal(badFormats[i])
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		if _, err := keyManager.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil
	if _, err := keyManager.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty array
	if _, err := keyManager.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
	// params field is unset
	formatNilParams := testutil.NewAESCTRHMACKeyFormat(32, commonpb.HashType_SHA256, 32, commonpb.HashType_SHA256, 16, 4096)
	formatNilParams.Params = nil
	serializedFormatNilParams, err := proto.Marshal(formatNilParams)
	if err != nil {
		t.Errorf("proto.Marshal(formatNilParams) err = %v, want nil", err)
	}
	if _, err := keyManager.NewKey(serializedFormatNilParams); err == nil {
		t.Errorf("keyManager.NewKey(serializedFormatNilParams) err = nil, want non-nil")
	}
}

func TestNewKeyDataBasic(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	for _, keySize := range []uint32{16, 32} {
		format := testutil.NewAESCTRHMACKeyFormat(keySize, commonpb.HashType_SHA256, keySize, commonpb.HashType_SHA256, 16, 4096)
		serializedFormat, err := proto.Marshal(format)
		if err != nil {
			t.Errorf("failed to marshal key: %s", err)
		}
		keyData, err := keyManager.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if keyData.TypeUrl != testutil.AESCTRHMACTypeURL {
			t.Errorf("incorrect type url")
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type")
		}
		key := new(ctrhmacpb.AesCtrHmacStreamingKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("incorrect key value")
		}
		if err := validateAESCTRHMACKey(key, format); err != nil {
			t.Errorf("%s", err)
		}
		p, err := registry.PrimitiveFromKeyData(keyData)
		if err != nil {
			t.Errorf("registry.PrimitiveFromKeyData(kd) err = %v, want nil", err)
		}
		_, ok := p.(*subtle.AESCTRHMAC)
		if !ok {
			t.Error("registry.PrimitiveFromKeyData(kd) did not return a AESCTRHMAC primitive")
		}
	}
}

func TestNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	badFormats := genInvalidAESCTRHMACKeyFormats()
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
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	if !keyManager.DoesSupport(testutil.AESCTRHMACTypeURL) {
		t.Errorf("AESCTRHMACKeyManager must support %s", testutil.AESCTRHMACTypeURL)
	}
	if keyManager.DoesSupport("some bad type") {
		t.Errorf("AESCTRHMACKeyManager must support only %s", testutil.AESCTRHMACTypeURL)
	}
}

func TestTypeURL(t *testing.T) {
	keyManager, err := registry.GetKeyManager(testutil.AESCTRHMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain AES-CTR-HMAC key manager: %s", err)
	}
	if keyManager.TypeURL() != testutil.AESCTRHMACTypeURL {
		t.Errorf("incorrect key type")
	}
}

func genInvalidAESCTRHMACKeyFormats() []proto.Message {
	return []proto.Message{
		// not AESCTRHMACKeyFormat
		testutil.NewAESCTRHMACKey(testutil.AESCTRHMACKeyVersion, 16, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),

		// invalid key size
		testutil.NewAESCTRHMACKeyFormat(17, commonpb.HashType_SHA256, 16, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKeyFormat(16, commonpb.HashType_SHA256, 17, commonpb.HashType_SHA256, 16, 4096),
		testutil.NewAESCTRHMACKeyFormat(33, commonpb.HashType_SHA256, 33, commonpb.HashType_SHA256, 16, 4096),
	}
}

func validateAESCTRHMACKey(key *ctrhmacpb.AesCtrHmacStreamingKey, format *ctrhmacpb.AesCtrHmacStreamingKeyFormat) error {
	if uint32(len(key.KeyValue)) != format.KeySize {
		return fmt.Errorf("incorrect key size")
	}
	if key.Version != testutil.AESCTRHMACKeyVersion {
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
	p, err := subtle.NewAESCTRHMAC(
		key.KeyValue,
		key.Params.HkdfHashType.String(),
		int(key.Params.DerivedKeySize),
		key.Params.HmacParams.Hash.String(),
		int(key.Params.HmacParams.TagSize),
		int(key.Params.CiphertextSegmentSize),
		0,
	)
	if err != nil {
		return fmt.Errorf("invalid key")
	}
	return validatePrimitive(p, key)
}

func validatePrimitive(p any, key *ctrhmacpb.AesCtrHmacStreamingKey) error {
	cipher := p.(*subtle.AESCTRHMAC)
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
