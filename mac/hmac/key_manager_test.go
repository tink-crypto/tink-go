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

package hmac_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/mac/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestKeyManagerPrimitiveWorks(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	keyValue := random.GetRandomBytes(20)
	testCases := []struct {
		name     string
		key      *hmacpb.HmacKey
		hashName string
		keyValue []byte
		tagSize  uint32
	}{
		{
			name: "SHA1",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA1,
					TagSize: 20,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA1",
			keyValue: keyValue,
			tagSize:  20,
		}, {
			name: "SHA256",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA256,
					TagSize: 32,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA256",
			keyValue: keyValue,
			tagSize:  32,
		}, {
			name: "SHA512",
			key: &hmacpb.HmacKey{
				Params: &hmacpb.HmacParams{
					Hash:    commonpb.HashType_SHA512,
					TagSize: 64,
				},
				KeyValue: keyValue,
			},
			hashName: "SHA512",
			keyValue: keyValue,
			tagSize:  64,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serializedKey, err := proto.Marshal(tc.key)
			if err != nil {
				t.Fatalf("proto.Marshal() err = %q, want nil", err)
			}
			p, err := km.Primitive(serializedKey)
			if err != nil {
				t.Fatalf("km.Primitive(serializedKey) err = %q, want nil", err)
			}
			mac, ok := p.(tink.MAC)
			if !ok {
				t.Fatal("mac is not a tink.MAC")
			}

			data := random.GetRandomBytes(20)
			tag, err := mac.ComputeMAC(data)
			if err != nil {
				t.Fatalf("mac.ComputeMAC() err = %q, want nil", err)
			}
			if err = mac.VerifyMAC(tag, data); err != nil {
				t.Fatalf("mac.VerifyMAC() err = %q, want nil", err)
			}

			wantMAC, err := subtle.NewHMAC(tc.hashName, tc.keyValue, tc.tagSize)
			if err != nil {
				t.Fatalf("subtle.NewHMAC() err = %v, want nil", err)
			}
			wantTag, err := wantMAC.ComputeMAC(data)
			if err != nil {
				t.Fatalf("wantMAC.ComputeMAC() err = %q, want nil", err)
			}
			if !bytes.Equal(tag, wantTag) {
				t.Errorf("tag = %s, want = %s", tag, wantTag)
			}
		})
	}
}

func TestKeyManagerPrimitiveWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	// invalid key
	testKeys := genInvalidHMACKeys()
	for i := 0; i < len(testKeys); i++ {
		serializedKey, err := proto.Marshal(testKeys[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.Primitive(serializedKey); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	if _, err := km.Primitive(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.Primitive([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestKeyManagerNewKeyMultipleTimes(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	serializedFormat, err := proto.Marshal(testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32))
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
		t.Errorf("key is repeated")
	}
}

func TestKeyManagerNewKeyBasic(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	testFormats := genValidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		key, err := km.NewKey(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		hmacKey, ok := key.(*hmacpb.HmacKey)
		if !ok {
			t.Errorf("key is not HmacKey")
		}
		format := testFormats[i]
		if format.KeySize != uint32(len(hmacKey.KeyValue)) ||
			hmacKey.Params.TagSize != format.Params.TagSize ||
			hmacKey.Params.Hash != format.Params.Hash {
			t.Errorf("key format and generated key do not match")
		}
	}
}

func TestKeyManagerNewKeyWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			fmt.Println("Error!")
		}
		if _, err := km.NewKey(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d: %s", i, err)
		}
	}
	if _, err := km.NewKey(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
	// empty input
	if _, err := km.NewKey([]byte{}); err == nil {
		t.Errorf("expect an error when input is empty")
	}
}

func TestKeyManagerNewKeyDataWorks(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("cannot obtain HMAC key manager: %s", err)
	}
	testFormats := genValidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Errorf("unexpected error in test case %d: %s", i, err)
		}
		if keyData.TypeUrl != testutil.HMACTypeURL {
			t.Errorf("incorrect type url in test case %d", i)
		}
		if keyData.KeyMaterialType != tinkpb.KeyData_SYMMETRIC {
			t.Errorf("incorrect key material type in test case %d", i)
		}
		key := new(hmacpb.HmacKey)
		if err := proto.Unmarshal(keyData.Value, key); err != nil {
			t.Errorf("invalid key value")
		}
		format := testFormats[i]
		if format.KeySize != uint32(len(key.KeyValue)) ||
			key.Params.TagSize != format.Params.TagSize ||
			key.Params.Hash != format.Params.Hash {
			t.Errorf("key format and generated key do not match")
		}
		p, err := registry.PrimitiveFromKeyData(keyData)
		if err != nil {
			t.Errorf("registry.PrimitiveFromKeyData(keyData) err = %v, want nil", err)
		}
		_, ok := p.(tink.MAC)
		if !ok {
			t.Error("registry.PrimitiveFromKeyData(keyData) did not return a tink.MAC")
		}
	}
}

func TestKeyManagerNewKeyDataWithInvalidInput(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	// invalid key formats
	testFormats := genInvalidHMACKeyFormats()
	for i := 0; i < len(testFormats); i++ {
		serializedFormat, err := proto.Marshal(testFormats[i])
		if err != nil {
			t.Fatalf("proto.Marshal() err = %q, want nil", err)
		}
		if _, err := km.NewKeyData(serializedFormat); err == nil {
			t.Errorf("expect an error in test case %d", i)
		}
	}
	// nil input
	if _, err := km.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when input is nil")
	}
}

func TestKeyManagerDoesSupport(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	if !km.DoesSupport(testutil.HMACTypeURL) {
		t.Errorf("HMACKeyManager must support %s", testutil.HMACTypeURL)
	}
	if km.DoesSupport("some bad type") {
		t.Errorf("HMACKeyManager must support only %s", testutil.HMACTypeURL)
	}
}

func TestKeyManagerTypeURL(t *testing.T) {
	km, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("HMAC key manager not found: %s", err)
	}
	if km.TypeURL() != testutil.HMACTypeURL {
		t.Errorf("incorrect GetKeyType()")
	}
}

func genInvalidHMACKeys() []proto.Message {
	badVersionKey := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	badVersionKey.Version++
	shortKey := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	shortKey.KeyValue = []byte{1, 1}
	nilParams := testutil.NewHMACKey(commonpb.HashType_SHA256, 32)
	nilParams.Params = nil
	return []proto.Message{
		// not a HMACKey
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// bad version
		badVersionKey,
		// tag size too big
		testutil.NewHMACKey(commonpb.HashType_SHA1, 21),
		testutil.NewHMACKey(commonpb.HashType_SHA256, 33),
		testutil.NewHMACKey(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHMACKey(commonpb.HashType_SHA256, 1),
		// key too short
		shortKey,
		// unknown hash type
		testutil.NewHMACKey(commonpb.HashType_UNKNOWN_HASH, 32),
		// params field is unset
		nilParams,
	}
}

func genInvalidHMACKeyFormats() []proto.Message {
	shortKeyFormat := testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32)
	shortKeyFormat.KeySize = 1
	nilParams := testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32)
	nilParams.Params = nil
	return []proto.Message{
		// not a HMACKeyFormat
		testutil.NewHMACParams(commonpb.HashType_SHA256, 32),
		// tag size too big
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA1, 21),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 33),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA512, 65),
		// tag size too small
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 1),
		// key too short
		shortKeyFormat,
		// unknown hash type
		testutil.NewHMACKeyFormat(commonpb.HashType_UNKNOWN_HASH, 32),
		// params field is unset
		nilParams,
	}
}

func genValidHMACKeyFormats() []*hmacpb.HmacKeyFormat {
	return []*hmacpb.HmacKeyFormat{
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA1, 20),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA256, 32),
		testutil.NewHMACKeyFormat(commonpb.HashType_SHA512, 64),
	}
}
