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

package hkdfprf_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/prf/hkdfprf" // To register the key manager.
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/prf/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hkdfpb "github.com/tink-crypto/tink-go/v2/proto/hkdf_prf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestKeyManagerGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testKeys := genValidHKDFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Errorf("km.Primitive() err = %q, want nil in test case %d", err, i)
		}
		if err := validateHKDFPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key
	testKeys := genInvalidHKDFKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive() err = nil, want non-nil in test case %d", i)
		}
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("km.Primitive() err = nil, want non-nil when input is nil")
	}
	// empty input
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("km.Primitive() err = nil, want non-nil when input is empty")
	}
}

func TestKeyManagerNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	serializedFormat, err := proto.Marshal(testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0)))
	if err != nil {
		t.Fatalf("proto.Marshal() err = %q, want nil", err)
	}
	keys := make(map[string]bool)
	nTest := 26
	for i := 0; i < nTest; i++ {
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKey() err = %q, want nil", err)
		}
		serializedKey, err := proto.Marshal(key)
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keys[string(serializedKey)] = true

		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKeyData() err = %q, want nil", err)
		}
		serializedKey = keyData.Value
		keys[string(serializedKey)] = true
	}
	if len(keys) != nTest*2 {
		t.Errorf("km.NewKey() and km.NewKeyData() produced repeated keys")
	}
}

func TestKeyManagerNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testFormats := genValidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("km.NewKey() err = %q, want nil in test case %d", err, i)
		}
		if err := validateHKDFKey(testFormats[i], key.(*hkdfpb.HkdfPrfKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestKeyManagerNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key formats
	testFormats := genInvalidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("km.NewKey() err = nil, want non-nil in test case %d", i)
		}
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("km.NewKey() err = nil, want non-nil when input is nil")
	}
	// empty input
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("km.NewKey() err = nil, want non-nil when input is empty")
	}
}

func TestKeyManagerNewKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testFormats := genValidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKeyData() err = %q, want nil in test case %d", err, i)
		}
		if keyData.GetTypeUrl() != testutil.HKDFPRFTypeURL {
			t.Errorf("km.NewKeyData() typeUrl = %q, want %q in test case %d", keyData.TypeUrl, testutil.HKDFPRFTypeURL, i)
		}
		if keyData.GetKeyMaterialType() != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("km.NewKeyData() keyMaterialType = %q, want %q in test case %d", keyData.KeyMaterialType, tinkpb.KeyData_SYMMETRIC, i)
		}
		key := new(hkdfpb.HkdfPrfKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Fatalf("proto.Unmarshal() err = %q, want nil", err)
		}
		if err := validateHKDFKey(testFormats[i], key); err != nil {
			t.Errorf("validateHKDFKey() err = %q, want nil", err)
		}
	}
}

func TestKeyManagerNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key formats
	testFormats := genInvalidHKDFKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("km.NewKeyData() err = nil, want non-nil in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("km.NewKeyData() err = nil, want non-nil when input is nil")
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	if !km.DoesSupport(testutil.HKDFPRFTypeURL) {
		t.Errorf("km.DoesSupport() = false, want true for %q", testutil.HKDFPRFTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("km.DoesSupport() = true, want false for %q", "some bad type")
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HKDFPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	if km.TypeURL() != testutil.HKDFPRFTypeURL {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testutil.HKDFPRFTypeURL)
	}
}

func genInvalidHKDFKeys() []proto.Message {
	badVersionKey := testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0))
	badVersionKey.Version++
	shortKey := testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0))
	shortKey.KeyValue = []byte{1, 1}
	nilParams := testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0))
	nilParams.Params = nil
	return []proto.Message{
		// not a HKDFPRFKey
		testutil.NewHKDFPRFParams(commonpb.HashType_SHA256, make([]byte, 0)),
		// bad version
		badVersionKey,
		// key too short
		shortKey,
		// SHA-1
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA1, make([]byte, 0)),
		// unknown hash type
		testutil.NewHKDFPRFKey(commonpb.HashType_UNKNOWN_HASH, make([]byte, 0)),
		// params field is unset
		nilParams,
	}
}

func genInvalidHKDFKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0))
	shortKeyFormat.KeySize = 1
	nilParams := testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0))
	nilParams.Params = nil
	return []proto.Message{
		// not a HKDFPRFKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// key too short
		shortKeyFormat,
		// SHA-1
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA1, make([]byte, 0)),
		// unknown hash type
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_UNKNOWN_HASH, make([]byte, 0)),
		// params field is unset
		nilParams,
	}
}

func genValidHKDFKeyFormats() []*hkdfpb.HkdfPrfKeyFormat {
	return []*hkdfpb.HkdfPrfKeyFormat{
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, make([]byte, 0)),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA512, make([]byte, 0)),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA256, []byte{0x01, 0x03, 0x42}),
		testutil.NewHKDFPRFKeyFormat(commonpb.HashType_SHA512, []byte{0x01, 0x03, 0x42}),
	}
}

func genValidHKDFKeys() []*hkdfpb.HkdfPrfKey {
	return []*hkdfpb.HkdfPrfKey{
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, make([]byte, 0)),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA512, make([]byte, 0)),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA256, []byte{0x01, 0x03, 0x42}),
		testutil.NewHKDFPRFKey(commonpb.HashType_SHA512, []byte{0x01, 0x03, 0x42}),
	}
}

// Checks whether the given HKDFPRFKey matches the given key HKDFPRFKeyFormat
func validateHKDFKey(format *hkdfpb.HkdfPrfKeyFormat, key *hkdfpb.HkdfPrfKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) ||
		key.Params.Hash != format.Params.Hash {
		return fmt.Errorf("key format and generated key do not match, format.KeySize = %d, len(key.KeyValue) = %d, format.Params.Hash = %v, key.Params.Hash = %v", format.KeySize, len(key.KeyValue), format.Params.Hash, key.Params.Hash)
	}
	p, err := subtle.NewHKDFPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue, key.Params.Salt)
	if err != nil {
		return fmt.Errorf("subtle.NewHKDFPRF() err = %q, want nil", err)
	}
	return validateHKDFPrimitive(p, key)
}

// validateHKDFPrimitive checks whether the given primitive matches the given HKDFPRFKey
func validateHKDFPrimitive(p any, key *hkdfpb.HkdfPrfKey) error {
	hkdfPrimitive := p.(prf.PRF)
	prfPrimitive, err := subtle.NewHKDFPRF(commonpb.HashType_name[int32(key.Params.Hash)], key.KeyValue, key.Params.Salt)
	if err != nil {
		return fmt.Errorf("subtle.NewHKDFPRF() err = %q, want nil for key material %q", err, hex.EncodeToString(key.KeyValue))
	}
	data := random.GetRandomBytes(20)
	res, err := hkdfPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("hkdfPrimitive.ComputePRF() err = %q, want nil", err)
	}
	if len(res) != 16 {
		return fmt.Errorf("hkdfPrimitive.ComputePRF() produced %d bytes, want 16", len(res))
	}
	res2, err := prfPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("prfPrimitive.ComputePRF() err = %q, want nil", err)
	}
	if len(res2) != 16 {
		return fmt.Errorf("prfPrimitive.ComputePRF() produced %d bytes, want 16", len(res2))
	}
	if !bytes.Equal(res, res2) {
		return fmt.Errorf("hkdfPrimitive.ComputePRF() and prfPrimitive.ComputePRF() produced different outputs for the same key and input")
	}
	return nil
}
