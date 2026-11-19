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
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	// Registers the AES-GCM key manager, which is used as a second registered
	// key type that doesn't match the test-only legacy keys.
	_ "github.com/tink-crypto/tink-go/v2/aead"
)

// collidingKeyManager is a key manager with the same type URL as the test-only
// legacy key manager registered by the keytest package.
type collidingKeyManager struct {
	testutil.DummyAEADKeyManager
}

func (km *collidingKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == keytest.LegacyKeyTypeURL
}

func (km *collidingKeyManager) TypeURL() string { return keytest.LegacyKeyTypeURL }

func mustMarshalLegacyKey(t *testing.T) []byte {
	t.Helper()
	serializedKey, err := proto.Marshal(&testonlypb.TestOnlyLegacyKey{
		Version:  0,
		KeyValue: []byte("0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("proto.Marshal() err = %s, want nil", err)
	}
	return serializedKey
}

func TestRegisterKeyManager(t *testing.T) {
	// get the test-only legacy key manager
	_, err := registry.GetKeyManager(keytest.LegacyKeyTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) err = %s, want nil", keytest.LegacyKeyTypeURL, err)
	}
	// some random typeurl
	if _, err = registry.GetKeyManager("some url"); err == nil {
		t.Errorf("registry.GetKeyManager(\"some url\") succeeded, want error")
	}
}

func TestRegisterKeyManagerWithCollision(t *testing.T) {
	// dummyKeyManager's typeURL is equal to that of the test-only legacy key manager
	dummyKeyManager := new(collidingKeyManager)
	// This should fail because overwriting is disallowed.
	err := registry.RegisterKeyManager(dummyKeyManager)
	if err == nil {
		t.Errorf("registry.RegisterKeyManager(dummyKeyManager) succeeded, want error")
	}

	km, err := registry.GetKeyManager(keytest.LegacyKeyTypeURL)
	if err != nil {
		t.Errorf("registry.GetKeyManager(%q) err = %s, want nil", keytest.LegacyKeyTypeURL, err)
	}
	// This should fail because overwriting is disallowed, even with the same key manager.
	err = registry.RegisterKeyManager(km)
	if err == nil {
		t.Errorf("registry.RegisterKeyManager(km) succeeded, want error")
	}
}

func TestNewKeyData(t *testing.T) {
	// new Keydata from a test-only legacy KeyTemplate
	keyData, err := registry.NewKeyData(keytest.TinkLegacyKeyTemplate())
	if err != nil {
		t.Fatalf("registry.NewKeyData(keytest.TinkLegacyKeyTemplate()) err = %s, want nil", err)
	}
	if keyData.TypeUrl != keytest.LegacyKeyTypeURL {
		t.Errorf("keyData.TypeUrl = %q, want %q", keyData.TypeUrl, keytest.LegacyKeyTypeURL)
	}
	key := new(testonlypb.TestOnlyLegacyKey)
	if err := proto.Unmarshal(keyData.Value, key); err != nil {
		t.Errorf("proto.Unmarshal() err = %s, want nil", err)
	}
	// nil
	if _, err := registry.NewKeyData(nil); err == nil {
		t.Errorf("registry.NewKeyData(nil) succeeded, want error")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := registry.NewKeyData(template); err == nil {
		t.Errorf("registry.NewKeyData(%v) succeeded, want error", template)
	}
}

func TestNewKey(t *testing.T) {
	// test-only legacy template
	legacyTemplate := keytest.TinkLegacyKeyTemplate()
	key, err := registry.NewKey(legacyTemplate)
	if err != nil {
		t.Fatalf("registry.NewKey(%v) err = %s, want nil", legacyTemplate, err)
	}
	legacyKey, ok := key.(*testonlypb.TestOnlyLegacyKey)
	if !ok {
		t.Fatalf("registry.NewKey(%v) = %T, want *testonlypb.TestOnlyLegacyKey", legacyTemplate, key)
	}
	legacyFormat := new(testonlypb.TestOnlyKeyFormat)
	if err := proto.Unmarshal(legacyTemplate.Value, legacyFormat); err != nil {
		t.Errorf("proto.Unmarshal() err = %s, want nil", err)
	}
	if legacyFormat.KeySize != uint32(len(legacyKey.KeyValue)) {
		t.Errorf("len(legacyKey.KeyValue) = %d, want %d", len(legacyKey.KeyValue), legacyFormat.KeySize)
	}
	// nil
	if _, err := registry.NewKey(nil); err == nil {
		t.Errorf("registry.NewKey(nil) succeeded, want error")
	}
	// unregistered type url
	template := &tinkpb.KeyTemplate{TypeUrl: "some url", Value: []byte{0}}
	if _, err := registry.NewKey(template); err == nil {
		t.Errorf("registry.NewKey(%v) succeeded, want error", template)
	}
}

func TestPrimitiveFromKeyData(t *testing.T) {
	// test-only legacy keydata
	keyData := &tinkpb.KeyData{
		TypeUrl:         keytest.LegacyKeyTypeURL,
		Value:           mustMarshalLegacyKey(t),
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	p, err := registry.PrimitiveFromKeyData(keyData)
	if err != nil {
		t.Errorf("registry.PrimitiveFromKeyData(keyData) err = %s, want nil", err)
	}
	if _, ok := p.(tink.AEAD); !ok {
		t.Errorf("registry.PrimitiveFromKeyData(keyData) = %T, want tink.AEAD", p)
	}
	// unregistered url
	keyData.TypeUrl = "some url"
	if _, err := registry.PrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("registry.PrimitiveFromKeyData(keyData) with TypeUrl = %q succeeded, want error", keyData.TypeUrl)
	}
	// unmatched url
	keyData.TypeUrl = testutil.AESGCMTypeURL
	if _, err := registry.PrimitiveFromKeyData(keyData); err == nil {
		t.Errorf("registry.PrimitiveFromKeyData(keyData) with TypeUrl = %q succeeded, want error", keyData.TypeUrl)
	}
	// nil
	if _, err := registry.PrimitiveFromKeyData(nil); err == nil {
		t.Errorf("registry.PrimitiveFromKeyData(nil) succeeded, want error")
	}
}

func TestPrimitive(t *testing.T) {
	// test-only legacy key
	serializedKey := mustMarshalLegacyKey(t)
	p, err := registry.Primitive(keytest.LegacyKeyTypeURL, serializedKey)
	if err != nil {
		t.Fatalf("registry.Primitive(%q, serializedKey) err = %s, want nil", keytest.LegacyKeyTypeURL, err)
	}
	if _, ok := p.(tink.AEAD); !ok {
		t.Errorf("registry.Primitive(%q, serializedKey) = %T, want tink.AEAD", keytest.LegacyKeyTypeURL, p)
	}
	// unregistered url
	if _, err := registry.Primitive("some url", serializedKey); err == nil {
		t.Errorf("registry.Primitive(\"some url\", serializedKey) succeeded, want error")
	}
	// unmatched url
	if _, err := registry.Primitive(testutil.AESGCMTypeURL, serializedKey); err == nil {
		t.Errorf("registry.Primitive(%q, serializedKey) succeeded, want error", testutil.AESGCMTypeURL)
	}
	// void key
	if _, err := registry.Primitive(keytest.LegacyKeyTypeURL, nil); err == nil {
		t.Errorf("registry.Primitive(%q, nil) succeeded, want error", keytest.LegacyKeyTypeURL)
	}
	if _, err := registry.Primitive(keytest.LegacyKeyTypeURL, []byte{}); err == nil {
		t.Errorf("registry.Primitive(%q, []byte{}) succeeded, want error", keytest.LegacyKeyTypeURL)
	}
	if _, err := registry.Primitive(keytest.LegacyKeyTypeURL, []byte{0}); err == nil {
		t.Errorf("registry.Primitive(%q, []byte{0}) succeeded, want error", keytest.LegacyKeyTypeURL)
	}
}

func TestRegisterKmsClient(t *testing.T) {
	client1, err := fakekms.NewClient("fake-kms://prefix1")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://prefix1\") err = %s, want nil", err)
	}
	client2, err := fakekms.NewClient("fake-kms://prefix2")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://prefix2\") err = %s, want nil", err)
	}
	registry.RegisterKMSClient(client1)
	registry.RegisterKMSClient(client2)
	output1, err := registry.GetKMSClient("fake-kms://prefix1-postfix")
	if err != nil {
		t.Errorf("registry.GetKMSClient(\"fake-kms://prefix1-postfix\") err = %s, want nil", err)
	}
	if output1 != client1 {
		t.Errorf("registry.GetKMSClient(\"fake-kms://prefix1-postfix\") = %v, want client1", output1)
	}
	output2, err := registry.GetKMSClient("fake-kms://prefix2-postfix")
	if err != nil {
		t.Errorf("registry.GetKMSClient(\"fake-kms://prefix2-postfix\") err = %s, want nil", err)
	}
	if output2 != client2 {
		t.Errorf("registry.GetKMSClient(\"fake-kms://prefix2-postfix\") = %v, want client2", output2)
	}
	_, err = registry.GetKMSClient("fake-kms://unknown-prefix")
	if err == nil {
		t.Errorf("registry.GetKMSClient(\"fake-kms://unknown-prefix\") succeeded, want error")
	}
	_, err = registry.GetKMSClient("bad-kms://unknown-prefix")
	if err == nil {
		t.Errorf("registry.GetKMSClient(\"bad-kms://unknown-prefix\") succeeded, want error")
	}
}

func TestRegisterTwoKmsClientsForSameUri_firstGetsReturned(t *testing.T) {
	abcClient, err := fakekms.NewClient("fake-kms://abc")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://abc\") err = %s, want nil", err)
	}
	registry.RegisterKMSClient(abcClient)

	abc123Client, err := fakekms.NewClient("fake-kms://abc123")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://abc123\") err = %s, want nil", err)
	}
	registry.RegisterKMSClient(abc123Client)

	// Both clients support "fake-kms://abc123". But abcClient was registered first.
	got, err := registry.GetKMSClient("fake-kms://abc123")
	if err != nil {
		t.Fatalf("registry.GetKMSClient(\"fake-kms://abc123\") err = %s, want nil", err)
	}
	if got != abcClient {
		t.Errorf("registry.GetKMSClient(\"fake-kms://abc123\") = %v, want abcClient", got)
	}
}

func TestClearKMSClients(t *testing.T) {
	client, err := fakekms.NewClient("fake-kms://xyz")
	if err != nil {
		t.Fatalf("fakekms.NewClient(\"fake-kms://xyz\") err = %s, want nil", err)
	}
	registry.RegisterKMSClient(client)

	_, err = registry.GetKMSClient("fake-kms://xyz-123")
	if err != nil {
		t.Errorf("registry.GetKMSClient(\"fake-kms://xyz-123\") err = %s, want nil", err)
	}

	registry.ClearKMSClients()

	_, err = registry.GetKMSClient("fake-kms://xyz-123")
	if err == nil {
		t.Errorf("registry.GetKMSClient(\"fake-kms://xyz-123\") succeeded, want error")
	}
}
