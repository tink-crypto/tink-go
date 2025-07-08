// Copyright 2019 Google LLC
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

package registry_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestRegisterKeyManager(t *testing.T) {
	// get HMACKeyManager
	_, err := registry.GetKeyManager(testutil.HMACTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	// get AESGCMKeyManager
	_, err = registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	// some random typeurl
	if _, err = registry.GetKeyManager("some url"); err == nil {
		t.Errorf("expect an error when a type url doesn't exist in the registry")
	}
}

func TestRegisterKeyManagerWithCollision(t *testing.T) {
	// dummyKeyManager's typeURL is equal to that of AESGCM
	var dummyKeyManager = new(testutil.DummyAEADKeyManager)
	// This should fail because overwriting is disallowed.
	err := registry.RegisterKeyManager(dummyKeyManager)
	if err == nil {
		t.Errorf("%s shouldn't be registered again", testutil.AESGCMTypeURL)
	}

	km, err := registry.GetKeyManager(testutil.AESGCMTypeURL)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	// This should fail because overwriting is disallowed, even with the same key manager.
	err = registry.RegisterKeyManager(km)
	if err == nil {
		t.Errorf("%s shouldn't be registered again", testutil.AESGCMTypeURL)
	}
}

func TestNewKeyData(t *testing.T) {
	// new Keydata from a Hmac KeyTemplate
	keyData, err := registry.NewKeyData(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if keyData.TypeUrl != testutil.HMACTypeURL {
		t.Errorf("invalid key data")
	}
	key := new(hmacpb.HmacKey)
	if err := proto.Unmarshal(keyData.Value, key); err != nil {
		t.Errorf("unexpected error when unmarshal HmacKey: %s", err)
	}
	// nil
	if _, err := registry.NewKeyData(nil); err == nil {
		t.Errorf("expect an error when key template is nil")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := registry.NewKeyData(template); err == nil {
		t.Errorf("expect an error when key template contains unregistered typeURL")
	}
}

func TestNewKey(t *testing.T) {
	// aead template
	aesGcmTemplate := aead.AES128GCMKeyTemplate()
	key, err := registry.NewKey(aesGcmTemplate)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	var aesGcmKey = key.(*gcmpb.AesGcmKey)
	aesGcmFormat := new(gcmpb.AesGcmKeyFormat)
	if err := proto.Unmarshal(aesGcmTemplate.Value, aesGcmFormat); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if aesGcmFormat.KeySize != uint32(len(aesGcmKey.KeyValue)) {
		t.Errorf("key doesn't match template")
	}
	//nil
	if _, err := registry.NewKey(nil); err == nil {
		t.Errorf("expect an error when key template is nil")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := registry.NewKey(template); err == nil {
		t.Errorf("expect an error when key template is not registered")
	}
}

func TestPrimitiveFromKeyData(t *testing.T) {
	// hmac keydata
	keyData := testutil.NewHMACKeyData(commonpb.HashType_SHA256, 16)
	p, err := registry.PrimitiveFromKeyData(keyData)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if _, ok := p.(tink.MAC); !ok {
		t.Errorf("registry.PrimitiveFromKeyData() e, _ = %T, want tink.MAC", p)
	}
	// unregistered url
	keyData.TypeUrl = "some url"
	if _, err := registry.PrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	keyData.TypeUrl = testutil.AESGCMTypeURL
	if _, err := registry.PrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("expect an error when typeURL doesn't match key")
	}
	// nil
	if _, err := registry.PrimitiveFromKeyData(nil); err == nil {
		t.Errorf("expect an error when key data is nil")
	}
}

func TestPrimitive(t *testing.T) {
	// hmac key
	key := testutil.NewHMACKey(commonpb.HashType_SHA256, 16)
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Fatalf("proto.Marshal() err = %s, want nil", err)
	}
	p, err := registry.Primitive(testutil.HMACTypeURL, serializedKey)
	if err != nil {
		t.Fatalf("registry.Primitive() err = %s, want nil", err)
	}
	if _, ok := p.(tink.MAC); !ok {
		t.Errorf("registry.Primitive() e, _ = %T, want tink.MAC", p)
	}
	// unregistered url
	if _, err := registry.Primitive("some url", serializedKey); err == nil {
		t.Errorf("expect an error when typeURL has not been registered")
	}
	// unmatched url
	if _, err := registry.Primitive(testutil.AESGCMTypeURL, serializedKey); err == nil {
		t.Errorf("expect an error when typeURL doesn't match key")
	}
	// void key
	if _, err := registry.Primitive(testutil.AESGCMTypeURL, nil); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := registry.Primitive(testutil.AESGCMTypeURL, []byte{}); err == nil {
		t.Errorf("expect an error when key is nil")
	}
	if _, err := registry.Primitive(testutil.AESGCMTypeURL, []byte{0}); err == nil {
		t.Errorf("expect an error when key is nil")
	}
}

func TestRegisterKmsClient(t *testing.T) {
	client1, err := fakekms.NewClient("fake-kms://prefix1")
	if err != nil {
		t.Fatalf("fakekms.NewClient('fake-kms://prefix1') failed: %v", err)
	}
	client2, err := fakekms.NewClient("fake-kms://prefix2")
	if err != nil {
		t.Fatalf("fakekms.NewClient('fake-kms://prefix2') failed: %v", err)
	}
	registry.RegisterKMSClient(client1)
	registry.RegisterKMSClient(client2)
	output1, err := registry.GetKMSClient("fake-kms://prefix1-postfix")
	if err != nil {
		t.Errorf("registry.GetKMSClient('fake-kms://prefix1-postfix') failed: %v", err)
	}
	if output1 != client1 {
		t.Errorf("registry.GetKMSClient('fake-kms://prefix1-postfix') did not return client1")
	}
	output2, err := registry.GetKMSClient("fake-kms://prefix2-postfix")
	if err != nil {
		t.Errorf("registry.GetKMSClient('fake-kms://prefix2-postfix') failed: %v", err)
	}
	if output2 != client2 {
		t.Errorf("registry.GetKMSClient('fake-kms://prefix2-postfix') did not return client2")
	}
	_, err = registry.GetKMSClient("fake-kms://unknown-prefix")
	if err == nil {
		t.Errorf("registry.GetKMSClient('fake-kms://unknown-prefix') succeeded, want fail")
	}
	_, err = registry.GetKMSClient("bad-kms://unknown-prefix")
	if err == nil {
		t.Errorf("registry.GetKMSClient('bad-kms://unknown-prefix') succeeded, want fail")
	}
}

func TestRegisterTwoKmsClientsForSameUri_firstGetsReturned(t *testing.T) {
	abcClient, err := fakekms.NewClient("fake-kms://abc")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://abc\") err = %q, want nil", err)
	}
	registry.RegisterKMSClient(abcClient)

	abc123Client, err := fakekms.NewClient("fake-kms://abc123")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://abc123\") err = %q, want nil", err)
	}
	registry.RegisterKMSClient(abc123Client)

	// Both clients support "fake-kms://abc123". But abcClient was registered first.
	got, err := registry.GetKMSClient("fake-kms://abc123")
	if err != nil {
		t.Fatalf("registry.GetKMSClient(\"fake-kms://abc123\") err = %q, want nil", err)
	}
	if got != abcClient {
		t.Errorf("registry.GetKMSClient(\"fake-kms://abc123\") = %q, want abcClient", got)
	}
}

func TestClearKMSClients(t *testing.T) {
	client, err := fakekms.NewClient("fake-kms://xyz")
	if err != nil {
		t.Fatalf("fakekms.NewClient('fake-kms://xyz') failed: %v", err)
	}
	registry.RegisterKMSClient(client)

	_, err = registry.GetKMSClient("fake-kms://xyz-123")
	if err != nil {
		t.Errorf("registry.GetKMSClient('fake-kms://xyz-123') failed: %v", err)
	}

	registry.ClearKMSClients()

	_, err = registry.GetKMSClient("fake-kms://xyz-123")
	if err == nil {
		t.Errorf("registry.GetKMSClient('fake-kms://xyz-123') succeeded, want fail")
	}
}
