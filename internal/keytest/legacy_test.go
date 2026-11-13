// Copyright 2026 Google LLC
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

package keytest_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	testonlypb "github.com/tink-crypto/tink-go/v2/proto/test_only_key_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func mustGetLegacyKeyManager(t *testing.T) registry.KeyManager {
	t.Helper()
	km, err := registry.GetKeyManager(keytest.LegacyKeyTypeURL)
	if err != nil {
		t.Fatalf("registry.GetKeyManager(%q) err = %v, want nil", keytest.LegacyKeyTypeURL, err)
	}
	return km
}

// mustGetLegacyKeyValue returns the key bytes of the test-only legacy key k.
func mustGetLegacyKeyValue(t *testing.T, k any) []byte {
	t.Helper()
	fallbackKey, ok := k.(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Fatalf("key is of type %T, want *protoserialization.FallbackProtoKey", k)
	}
	keyData := protoserialization.GetKeySerialization(fallbackKey).KeyData()
	if got, want := keyData.GetTypeUrl(), keytest.LegacyKeyTypeURL; got != want {
		t.Fatalf("keyData.GetTypeUrl() = %q, want %q", got, want)
	}
	protoKey := new(testonlypb.TestOnlyLegacyKey)
	if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
		t.Fatalf("proto.Unmarshal(keyData.GetValue(), protoKey) err = %v, want nil", err)
	}
	return protoKey.GetKeyValue()
}

func TestLegacyKeyManagerIsRegistered(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	if got, want := km.TypeURL(), keytest.LegacyKeyTypeURL; got != want {
		t.Errorf("km.TypeURL() = %q, want %q", got, want)
	}
	if !km.DoesSupport(keytest.LegacyKeyTypeURL) {
		t.Errorf("km.DoesSupport(%q) = false, want true", keytest.LegacyKeyTypeURL)
	}
	if km.DoesSupport(testOnlyKeyTypeURL) {
		t.Errorf("km.DoesSupport(%q) = true, want false", testOnlyKeyTypeURL)
	}
}

func TestLegacyKeyTemplate(t *testing.T) {
	for _, outputPrefixType := range []tinkpb.OutputPrefixType{
		tinkpb.OutputPrefixType_TINK,
		tinkpb.OutputPrefixType_CRUNCHY,
		tinkpb.OutputPrefixType_LEGACY,
		tinkpb.OutputPrefixType_RAW,
	} {
		t.Run(outputPrefixType.String(), func(t *testing.T) {
			got := keytest.LegacyKeyTemplate(outputPrefixType)
			want := &tinkpb.KeyTemplate{
				TypeUrl:          keytest.LegacyKeyTypeURL,
				Value:            mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: 16}),
				OutputPrefixType: outputPrefixType,
			}
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Errorf("keytest.LegacyKeyTemplate(%v) returned unexpected diff (-want +got):\n%s", outputPrefixType, diff)
			}
		})
	}
}

func TestLegacyKeyManagerNewKeyData(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	serializedFormat := keytest.LegacyKeyTemplate(tinkpb.OutputPrefixType_TINK).GetValue()

	var keyValues [][]byte
	for i := 0; i < 2; i++ {
		keyData, err := km.NewKeyData(serializedFormat)
		if err != nil {
			t.Fatalf("km.NewKeyData(%x) err = %v, want nil", serializedFormat, err)
		}
		if got, want := keyData.GetTypeUrl(), keytest.LegacyKeyTypeURL; got != want {
			t.Errorf("keyData.GetTypeUrl() = %q, want %q", got, want)
		}
		if got, want := keyData.GetKeyMaterialType(), tinkpb.KeyData_SYMMETRIC; got != want {
			t.Errorf("keyData.GetKeyMaterialType() = %v, want %v", got, want)
		}
		protoKey := new(testonlypb.TestOnlyLegacyKey)
		if err := proto.Unmarshal(keyData.GetValue(), protoKey); err != nil {
			t.Fatalf("proto.Unmarshal(keyData.GetValue(), protoKey) err = %v, want nil", err)
		}
		if got, want := protoKey.GetVersion(), uint32(0); got != want {
			t.Errorf("protoKey.GetVersion() = %d, want %d", got, want)
		}
		if got, want := len(protoKey.GetKeyValue()), 16; got != want {
			t.Errorf("len(protoKey.GetKeyValue()) = %d, want %d", got, want)
		}
		keyValues = append(keyValues, protoKey.GetKeyValue())
	}
	if bytes.Equal(keyValues[0], keyValues[1]) {
		t.Errorf("km.NewKeyData(%x) returned the same key value twice: %x", serializedFormat, keyValues[0])
	}
}

func TestLegacyKeyManagerNewKey(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	serializedFormat := keytest.LegacyKeyTemplate(tinkpb.OutputPrefixType_TINK).GetValue()
	m, err := km.NewKey(serializedFormat)
	if err != nil {
		t.Fatalf("km.NewKey(%x) err = %v, want nil", serializedFormat, err)
	}
	protoKey, ok := m.(*testonlypb.TestOnlyLegacyKey)
	if !ok {
		t.Fatalf("km.NewKey(%x) = %T, want *testonlypb.TestOnlyLegacyKey", serializedFormat, m)
	}
	if got, want := protoKey.GetVersion(), uint32(0); got != want {
		t.Errorf("protoKey.GetVersion() = %d, want %d", got, want)
	}
	if got, want := len(protoKey.GetKeyValue()), 16; got != want {
		t.Errorf("len(protoKey.GetKeyValue()) = %d, want %d", got, want)
	}
}

func TestLegacyKeyManagerNewKeyFails(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	for _, tc := range []struct {
		name             string
		serializedFormat []byte
	}{
		{
			name:             "empty key format",
			serializedFormat: nil,
		},
		{
			name:             "malformed key format",
			serializedFormat: []byte("malformed"),
		},
		{
			name:             "key size too small",
			serializedFormat: mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: 15}),
		},
		{
			name:             "key size too large",
			serializedFormat: mustMarshal(t, &testonlypb.TestOnlyKeyFormat{KeySize: 32}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.NewKey(tc.serializedFormat); err == nil {
				t.Errorf("km.NewKey(%x) err = nil, want error", tc.serializedFormat)
			}
			if _, err := km.NewKeyData(tc.serializedFormat); err == nil {
				t.Errorf("km.NewKeyData(%x) err = nil, want error", tc.serializedFormat)
			}
		})
	}
}

func TestLegacyKeyManagerPrimitive(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	serializedKey := mustMarshal(t, &testonlypb.TestOnlyLegacyKey{Version: 0, KeyValue: key128Bits})
	p, err := km.Primitive(serializedKey)
	if err != nil {
		t.Fatalf("km.Primitive(%x) err = %v, want nil", serializedKey, err)
	}
	a, ok := p.(tink.AEAD)
	if !ok {
		t.Fatalf("km.Primitive(%x) = %T, want tink.AEAD", serializedKey, p)
	}
	// The primitive doesn't add any output prefix: it must be compatible with
	// the corresponding DummyAEAD.
	dummyAEAD := &testutil.DummyAEAD{Name: hex.EncodeToString(key128Bits)}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	for _, tc := range []struct {
		name      string
		encrypter tink.AEAD
		decrypter tink.AEAD
	}{
		{name: "primitive to primitive", encrypter: a, decrypter: a},
		{name: "primitive to DummyAEAD", encrypter: a, decrypter: dummyAEAD},
		{name: "DummyAEAD to primitive", encrypter: dummyAEAD, decrypter: a},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := tc.encrypter.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("encrypter.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			got, err := tc.decrypter.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("decrypter.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("decrypter.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, plaintext)
			}
		})
	}

	// A primitive for another key must not decrypt.
	otherSerializedKey := mustMarshal(t, &testonlypb.TestOnlyLegacyKey{Version: 0, KeyValue: otherKey128Bits})
	otherPrimitive, err := km.Primitive(otherSerializedKey)
	if err != nil {
		t.Fatalf("km.Primitive(%x) err = %v, want nil", otherSerializedKey, err)
	}
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
	}
	if _, err := otherPrimitive.(tink.AEAD).Decrypt(ciphertext, associatedData); err == nil {
		t.Errorf("otherPrimitive.Decrypt(%x, %x) err = nil, want error", ciphertext, associatedData)
	}
}

func TestLegacyKeyManagerPrimitiveFails(t *testing.T) {
	km := mustGetLegacyKeyManager(t)
	for _, tc := range []struct {
		name          string
		serializedKey []byte
	}{
		{
			name:          "empty key",
			serializedKey: nil,
		},
		{
			name:          "malformed key",
			serializedKey: []byte("malformed"),
		},
		{
			name:          "wrong version",
			serializedKey: mustMarshal(t, &testonlypb.TestOnlyLegacyKey{Version: 1, KeyValue: key128Bits}),
		},
		{
			name:          "key too small",
			serializedKey: mustMarshal(t, &testonlypb.TestOnlyLegacyKey{Version: 0, KeyValue: key128Bits[:15]}),
		},
		{
			name:          "key too large",
			serializedKey: mustMarshal(t, &testonlypb.TestOnlyLegacyKey{Version: 0, KeyValue: key256Bits}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.Primitive(tc.serializedKey); err == nil {
				t.Errorf("km.Primitive(%x) err = nil, want error", tc.serializedKey)
			}
		})
	}
}

type legacyHandleTestCase struct {
	name             string
	outputPrefixType tinkpb.OutputPrefixType
	// wantPrefix returns the expected ciphertext prefix for the given key ID.
	wantPrefix func(keyID uint32) []byte
}

func legacyHandleTestCases() []legacyHandleTestCase {
	return []legacyHandleTestCase{
		{
			name:             "TINK",
			outputPrefixType: tinkpb.OutputPrefixType_TINK,
			wantPrefix: func(keyID uint32) []byte {
				return binary.BigEndian.AppendUint32([]byte{cryptofmt.TinkStartByte}, keyID)
			},
		},
		{
			name:             "CRUNCHY",
			outputPrefixType: tinkpb.OutputPrefixType_CRUNCHY,
			wantPrefix: func(keyID uint32) []byte {
				return binary.BigEndian.AppendUint32([]byte{cryptofmt.LegacyStartByte}, keyID)
			},
		},
		{
			// Same output prefix as CRUNCHY.
			name:             "LEGACY",
			outputPrefixType: tinkpb.OutputPrefixType_LEGACY,
			wantPrefix: func(keyID uint32) []byte {
				return binary.BigEndian.AppendUint32([]byte{cryptofmt.LegacyStartByte}, keyID)
			},
		},
		{
			name:             "RAW",
			outputPrefixType: tinkpb.OutputPrefixType_RAW,
			wantPrefix:       func(keyID uint32) []byte { return nil },
		},
	}
}

func mustCreateLegacyHandle(t *testing.T, outputPrefixType tinkpb.OutputPrefixType) *keyset.Handle {
	t.Helper()
	template := keytest.LegacyKeyTemplate(outputPrefixType)
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) err = %v, want nil", template, err)
	}
	return handle
}

func TestLegacyKeyIsParsedAsFallbackProtoKey(t *testing.T) {
	for _, tc := range legacyHandleTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			handle := mustCreateLegacyHandle(t, tc.outputPrefixType)
			entry, err := handle.Primary()
			if err != nil {
				t.Fatalf("handle.Primary() err = %v, want nil", err)
			}
			// There is no proto serialization for this key type, so the key is not a
			// [keytest.Key], but a fallback proto key.
			switch k := entry.Key().(type) {
			case *protoserialization.FallbackProtoKey:
				// Expected.
			default:
				t.Fatalf("entry.Key() is of type %T, want *protoserialization.FallbackProtoKey", k)
			}
			if got, want := len(mustGetLegacyKeyValue(t, entry.Key())), 16; got != want {
				t.Errorf("len(keyValue) = %d, want %d", got, want)
			}
		})
	}
}

func TestLegacyKeyPrimitiveFromRegistryConfigIsLegacy(t *testing.T) {
	for _, tc := range legacyHandleTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			handle := mustCreateLegacyHandle(t, tc.outputPrefixType)
			entry, err := handle.Primary()
			if err != nil {
				t.Fatalf("handle.Primary() err = %v, want nil", err)
			}
			config := &registryconfig.RegistryConfig{}
			if _, err := config.PrimitiveFromKey(entry.Key(), internalapi.Token{}); err != nil {
				t.Fatalf("config.PrimitiveFromKey(entry.Key(), internalapi.Token{}) err = %v, want nil", err)
			}

			a, isLegacy, err := factoryutil.PrimitiveFromKey[tink.AEAD](entry.Key(), config)
			if err != nil {
				t.Fatalf("factoryutil.PrimitiveFromKey[tink.AEAD](entry.Key(), config) err = %v, want nil", err)
			}
			if !isLegacy {
				t.Errorf("factoryutil.PrimitiveFromKey[tink.AEAD](entry.Key(), config) isLegacy = false, want true")
			}

			// The legacy primitive is the one created by the key manager, without
			// output prefix.
			plaintext := []byte("plaintext")
			associatedData := []byte("associatedData")
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			dummyAEAD := &testutil.DummyAEAD{Name: hex.EncodeToString(mustGetLegacyKeyValue(t, entry.Key()))}
			got, err := dummyAEAD.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("dummyAEAD.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("dummyAEAD.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, plaintext)
			}
		})
	}
}

func TestLegacyKeyAEADFactoryEncryptDecrypt(t *testing.T) {
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	for _, tc := range legacyHandleTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			handle := mustCreateLegacyHandle(t, tc.outputPrefixType)
			entry, err := handle.Primary()
			if err != nil {
				t.Fatalf("handle.Primary() err = %v, want nil", err)
			}
			a, err := aead.New(handle)
			if err != nil {
				t.Fatalf("aead.New(handle) err = %v, want nil", err)
			}
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			got, err := a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("a.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, plaintext)
			}

			// The ciphertext is the output prefix, which is added by the factory,
			// followed by the ciphertext of the primitive created by the key manager.
			wantPrefix := tc.wantPrefix(entry.KeyID())
			if !bytes.HasPrefix(ciphertext, wantPrefix) {
				t.Fatalf("ciphertext = %x, want prefix %x", ciphertext, wantPrefix)
			}
			dummyAEAD := &testutil.DummyAEAD{Name: hex.EncodeToString(mustGetLegacyKeyValue(t, entry.Key()))}
			rawCiphertext := ciphertext[len(wantPrefix):]
			got, err = dummyAEAD.Decrypt(rawCiphertext, associatedData)
			if err != nil {
				t.Fatalf("dummyAEAD.Decrypt(%x, %x) err = %v, want nil", rawCiphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("dummyAEAD.Decrypt(%x, %x) = %x, want %x", rawCiphertext, associatedData, got, plaintext)
			}

			// And vice versa.
			rawCiphertext, err = dummyAEAD.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("dummyAEAD.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			ciphertext = slices.Concat(wantPrefix, rawCiphertext)
			got, err = a.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("a.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("a.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, plaintext)
			}
		})
	}
}

func TestLegacyKeyHandleWriteRead(t *testing.T) {
	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	for _, tc := range legacyHandleTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			handle := mustCreateLegacyHandle(t, tc.outputPrefixType)
			buf := new(bytes.Buffer)
			if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buf)); err != nil {
				t.Fatalf("insecurecleartextkeyset.Write(handle, w) err = %v, want nil", err)
			}
			parsedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buf))
			if err != nil {
				t.Fatalf("insecurecleartextkeyset.Read(r) err = %v, want nil", err)
			}
			if diff := cmp.Diff(handle.KeysetInfo(), parsedHandle.KeysetInfo(), protocmp.Transform()); diff != "" {
				t.Errorf("parsedHandle.KeysetInfo() returned unexpected diff (-want +got):\n%s", diff)
			}
			entry, err := handle.Primary()
			if err != nil {
				t.Fatalf("handle.Primary() err = %v, want nil", err)
			}
			parsedEntry, err := parsedHandle.Primary()
			if err != nil {
				t.Fatalf("parsedHandle.Primary() err = %v, want nil", err)
			}
			if !parsedEntry.Key().Equal(entry.Key()) {
				t.Errorf("parsedEntry.Key().Equal(entry.Key()) = false, want true")
			}

			// The parsed handle must decrypt what the original one encrypted.
			a, err := aead.New(handle)
			if err != nil {
				t.Fatalf("aead.New(handle) err = %v, want nil", err)
			}
			parsedAEAD, err := aead.New(parsedHandle)
			if err != nil {
				t.Fatalf("aead.New(parsedHandle) err = %v, want nil", err)
			}
			ciphertext, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("a.Encrypt(%x, %x) err = %v, want nil", plaintext, associatedData, err)
			}
			got, err := parsedAEAD.Decrypt(ciphertext, associatedData)
			if err != nil {
				t.Fatalf("parsedAEAD.Decrypt(%x, %x) err = %v, want nil", ciphertext, associatedData, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("parsedAEAD.Decrypt(%x, %x) = %x, want %x", ciphertext, associatedData, got, plaintext)
			}
		})
	}
}
