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

package aescmac_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	_ "github.com/tink-crypto/tink-go/v2/prf/aescmac" // Register the key manager.
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/prf/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	cmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_prf_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestKeyManagerGetPrimitiveBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testKeys := genValidCMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		p, err := km.Primitive(serializedKey)
		if err != nil {
			t.Fatalf("km.Primitive() err = %q, want nil in test case %d", err, i)
		}
		if err := validateCMACPrimitive(p, testKeys[i]); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestKeyManagerGetPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key
	testKeys := genInvalidCMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("km.Primitive() err = nil, want error in test case %d", i)
		}
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("km.Primitive() err = nil, want error when input is nil")
	}
	// empty input
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("km.Primitive() err = nil, want error when input is empty")
	}
}

func TestKeyManagerNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	serializedFormat, err := proto.Marshal(testutil.NewAESCMACPRFKeyFormat())
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
		t.Errorf("km.NewKey() or km.NewKeyData() returned repeated keys")
	}
}

func TestKeyManagerNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("km.NewKey() err = %q, want nil in test case %d", err, i)
		}
		if err := validateKey(testFormats[i], key.(*cmacpb.AesCmacPrfKey)); err != nil {
			t.Errorf("%s", err)
		}
	}
}

func TestKeyManagerNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key formats
	testFormats := genInvalidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			fmt.Println("Error!")
		}
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("km.NewKey() err = nil, want error in test case %d: %s", i, err)
		}
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("km.NewKey() err = nil, want error when input is nil")
	}
	// empty input
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("km.NewKey() err = nil, want error when input is empty")
	}
}

func TestKeyManagerNewKeyDataBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	testFormats := genValidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("km.NewKeyData() err = %q, want nil in test case %d", err, i)
		}
		if keyData.TypeUrl != testutil.AESCMACPRFTypeURL {
			t.Errorf("km.NewKeyData() returned incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("km.NewKeyData() returned incorrect key material type in test case %d", i)
		}
		key := new(cmacpb.AesCmacPrfKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("proto.Unmarshal() err = %q, want nil", err)
		}
		if err := validateKey(testFormats[i], key); err != nil {
			t.Errorf("validateKey() err = %q, want nil", err)
		}
	}
}

func TestKeyManagerNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	// invalid key formats
	testFormats := genInvalidCMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("km.NewKeyData() err = nil, want error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("km.NewKeyData() err = nil, want error when input is nil")
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	if !km.DoesSupport(testutil.AESCMACPRFTypeURL) {
		t.Errorf("km.DoesSupport() = false, want true for %s", testutil.AESCMACPRFTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("km.DoesSupport() = true, want false for some bad type")
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.AESCMACPRFTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager() err = %q, want nil", err)
	}
	if km.TypeURL() != testutil.AESCMACPRFTypeURL {
		t.Errorf("km.TypeURL() = %q, want %q", km.TypeURL(), testutil.AESCMACPRFTypeURL)
	}
}

func genInvalidCMACKeys() []proto.Message {
	badVersionKey := testutil.NewAESCMACPRFKey()
	badVersionKey.Version++
	shortKey := testutil.NewAESCMACPRFKey()
	shortKey.KeyValue = []byte{1, 1}
	return []proto.Message{
		// not a AESCMACPRFKey
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// key too short
		shortKey,
	}
}

func genInvalidCMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewAESCMACPRFKeyFormat()
	shortKeyFormat.KeySize = 1
	return []proto.Message{
		// not a AESCMACPRFKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// key too short
		shortKeyFormat,
	}
}

func genValidCMACKeyFormats() []*cmacpb.AesCmacPrfKeyFormat {
	return []*cmacpb.AesCmacPrfKeyFormat{
		testutil.NewAESCMACPRFKeyFormat(),
	}
}

func genValidCMACKeys() []*cmacpb.AesCmacPrfKey {
	return []*cmacpb.AesCmacPrfKey{
		testutil.NewAESCMACPRFKey(),
	}
}

// Checks whether the given CMACPRFKey matches the given key AESCMACPRFKeyFormat
func validateKey(format *cmacpb.AesCmacPrfKeyFormat, key *cmacpb.AesCmacPrfKey) error {
	if format.KeySize != uint32(len(key.KeyValue)) {
		return fmt.Errorf("key format and generated key do not match, format.KeySize = %d, len(key.KeyValue) = %d", format.KeySize, len(key.KeyValue))
	}
	p, err := subtle.NewAESCMACPRF(key.KeyValue)
	if err != nil {
		return fmt.Errorf("subtle.NewAESCMACPRF() err = %q, want nil", err)
	}
	return validateCMACPrimitive(p, key)
}

// validateCMACPrimitive checks whether the given primitive matches the given AESCMACPRFKey
func validateCMACPrimitive(p any, key *cmacpb.AesCmacPrfKey) error {
	cmacPrimitive := p.(prf.PRF)
	prfPrimitive, err := subtle.NewAESCMACPRF(key.KeyValue)
	if err != nil {
		return fmt.Errorf("subtle.NewAESCMACPRF() err = %q, want nil for key material %q", err, hex.EncodeToString(key.KeyValue))
	}
	data := random.GetRandomBytes(20)
	res, err := cmacPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("cmacPrimitive.ComputePRF() err = %q, want nil", err)
	}
	if len(res) != 16 {
		return fmt.Errorf("cmacPrimitive.ComputePRF() len = %v, want 16", len(res))
	}
	res2, err := prfPrimitive.ComputePRF(data, 16)
	if err != nil {
		return fmt.Errorf("prfPrimitive.ComputePRF() err = %q, want nil", err)
	}
	if len(res2) != 16 {
		return fmt.Errorf("prfPrimitive.ComputePRF() len = %v, want 16", len(res2))
	}
	if !bytes.Equal(res, res2) {
		return fmt.Errorf("cmacPrimitive.ComputePRF() and prfPrimitive.ComputePRF() produced different output for the same key and input")
	}
	return nil
}
