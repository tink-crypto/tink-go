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

package keyset_test

import (
	"bytes"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestNewHandle(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Errorf("keyset.NewHandle(template) = %v, want nil", err)
	}
	ks := testkeyset.KeysetMaterial(handle)
	if len(ks.Key) != 1 {
		t.Errorf("len(ks.Key) = %d, want 1", len(ks.Key))
	}
	key := ks.Key[0]
	if ks.PrimaryKeyId != key.KeyId {
		t.Errorf("ks.PrimaryKeyId = %d, want %d", ks.PrimaryKeyId, key.KeyId)
	}
	if key.KeyData.TypeUrl != template.TypeUrl {
		t.Errorf("key.KeyData.TypeUrl = %v, want %v", key.KeyData.TypeUrl, template.TypeUrl)
	}
	if _, err = mac.New(handle); err != nil {
		t.Errorf("mac.New(handle) err = %v, want nil", err)
	}
}

func TestKeysetMaterialMakesACopy(t *testing.T) {
	wantProtoKeyset := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{
		testutil.NewKey(testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC), tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK),
	})
	handle, err := testkeyset.NewHandle(wantProtoKeyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle(wantProtoKeyset) = %v, want nil", err)
	}
	gotProtoKeyset := testkeyset.KeysetMaterial(handle)
	if wantProtoKeyset == gotProtoKeyset {
		t.Errorf("testkeyset.KeysetMaterial(handle) = %v, want a copy of %v", gotProtoKeyset, wantProtoKeyset)
	}
	if !proto.Equal(gotProtoKeyset, wantProtoKeyset) {
		t.Errorf("testkeyset.NewHandle(wantProtoKeyset) = %v, want %v", gotProtoKeyset, wantProtoKeyset)
	}
}

func TestNewHandleExistingKeyset(t *testing.T) {
	testCases := []struct {
		name string
		ks   *tinkpb.Keyset
	}{
		{
			name: "one enabled key",
			ks: &tinkpb.Keyset{
				PrimaryKeyId: 1,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyId:            1,
						Status:           tinkpb.KeyStatusType_ENABLED,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
						KeyData:          testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC),
					},
				},
			},
		},
		{
			name: "multiple keys",
			ks: &tinkpb.Keyset{
				PrimaryKeyId: 1,
				Key: []*tinkpb.Keyset_Key{
					&tinkpb.Keyset_Key{
						KeyId:            1,
						Status:           tinkpb.KeyStatusType_ENABLED,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
						KeyData:          testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC),
					},
					&tinkpb.Keyset_Key{
						KeyId:            2,
						Status:           tinkpb.KeyStatusType_DISABLED,
						OutputPrefixType: tinkpb.OutputPrefixType_TINK,
						KeyData:          testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wantProtoKeyset := tc.ks
			handle, err := testkeyset.NewHandle(wantProtoKeyset)
			if err != nil {
				t.Fatalf("testkeyset.NewHandle(wantProtoKeyset) = %v, want nil", err)
			}
			gotProtoKeyset := testkeyset.KeysetMaterial(handle)
			if !proto.Equal(gotProtoKeyset, wantProtoKeyset) {
				t.Errorf("testkeyset.NewHandle(wantProtoKeyset) = %v, want %v", gotProtoKeyset, wantProtoKeyset)
			}
		})
	}
}

func TestNewHandleWithInvalidTypeURLFails(t *testing.T) {
	// template with unknown TypeURL
	invalidTemplate := mac.HMACSHA256Tag128KeyTemplate()
	invalidTemplate.TypeUrl = "some unknown TypeURL"
	if _, err := keyset.NewHandle(invalidTemplate); err == nil {
		t.Errorf("keyset.NewHandle(invalidTemplate) err = nil, want error")
	}
}

func TestNewHandleWithNilTemplateFails(t *testing.T) {
	if _, err := keyset.NewHandle(nil); err == nil {
		t.Error("keyset.NewHandle(nil) err = nil, want error")
	}
}

func TestWriteAndReadInBinary(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead) err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	gotHandle, err := keyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("keyset.Read() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(handle)) {
		t.Fatalf("keyset.Read() = %v, want %v", gotHandle, handle)
	}
}

func TestWriteAndReadInJSON(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.Write(keyset.NewJSONWriter(buff), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("h.Write(keyset.NewJSONWriter(buff), keysetEncryptionAead) err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	gotHandle, err := keyset.Read(keyset.NewJSONReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead)
	if err != nil {
		t.Fatalf("keyset.Read() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(gotHandle), testkeyset.KeysetMaterial(handle)) {
		t.Fatalf("keyset.Read() = %v, want %v", gotHandle, handle)
	}
}

func TestWriteAndReadWithAssociatedData(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	associatedData := []byte{0x01, 0x02}

	buff := &bytes.Buffer{}
	err = handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	handle2, err := keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("keyset.ReadWithAssociatedData() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle2)) {
		t.Errorf("keyset.ReadWithAssociatedData() = %v, want %v", handle2, handle)
	}
}

func TestReadWithMismatchedAssociatedData(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate()) err = %v, want nil", err)
	}
	associatedData := []byte{0x01, 0x02}

	buff := &bytes.Buffer{}
	err = handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData)
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData() err = %v, want nil", err)
	}
	encrypted := buff.Bytes()

	invalidAssociatedData := []byte{0x01, 0x03}
	_, err = keyset.ReadWithAssociatedData(keyset.NewBinaryReader(bytes.NewBuffer(encrypted)), keysetEncryptionAead, invalidAssociatedData)
	if err == nil {
		t.Errorf("keyset.ReadWithAssociatedData() err = nil, want err")
	}
}

func TestPrimaryReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	_, err := handle.Primary()
	if err == nil {
		t.Errorf("handle.Primary() err = nil, want err")
	}
}

func TestLenReturnsZeroWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	length := handle.Len()
	if length != 0 {
		t.Errorf("handle.Len() = %v, want 0", length)
	}
}

func TestPublicReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	_, err := handle.Public()
	if err == nil {
		t.Errorf("handle.Public() err = nil, want err")
	}
}

func TestEntryReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	_, err := handle.Entry(0)
	if err == nil {
		t.Errorf("handle.Entry(0) err = nil, want err")
	}
}

func TestPrimitivesReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	_, err := handle.Primitives()
	if err == nil {
		t.Errorf("handle.Primitives() err = nil, want err")
	}
}

func TestPrimitivesWithKeyManagerReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	_, err := handle.PrimitivesWithKeyManager(&testKeyManager{})
	if err == nil {
		t.Errorf("handle.PrimitivesWithKeyManager(&testKeyManager{}) err = nil, want err")
	}
}

func TestKeysetInfoPanicsWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("handle.KeysetInfo() did not panic")
		}
	}()
	_ = handle.KeysetInfo()
}

func TestStringPanicsWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("handle.String() did not panic")
		}
	}()
	_ = handle.String()
}

func TestWriteReturnsErrorWithZeroValueHandle(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAEAD, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle := &keyset.Handle{}
	buff := &bytes.Buffer{}
	err = handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAEAD)
	if err == nil {
		t.Error("handle.Write() err = nil, want err")
	}
}

func TestWriteWithAssociatedDataReturnsErrorWithZeroValueHandle(t *testing.T) {
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	keysetEncryptionAEAD, err := aead.New(keysetEncryptionHandle)
	if err != nil {
		t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
	}

	handle := &keyset.Handle{}
	buff := &bytes.Buffer{}
	err = handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAEAD, []byte("aad"))
	if err == nil {
		t.Error("handle.WriteWithAssociatedData() err = nil, want err")
	}
}

func TestWriteWithNoSecretsReturnsErrorWithZeroValueHandle(t *testing.T) {
	handle := &keyset.Handle{}
	buff := &bytes.Buffer{}
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)); err == nil {
		t.Error("handle.WriteWithNoSecrets() err = nil, want err")
	}
}

func TestWriteAndReadWithNoSecrets(t *testing.T) {
	// Create a keyset that contains a public key.
	privateHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}
	handle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), masterKey, associatedData) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	// Using ReadWithNoSecrets.
	handle2, err := keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err != nil {
		t.Fatalf("keyset.ReadWithNoSecrets() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle2)) {
		t.Fatalf("keyset.ReadWithNoSecrets() = %v, want %v", handle2, handle)
	}

	// Using Read() and then NewHandleWithNoSecrets.
	reader := keyset.NewBinaryReader(bytes.NewBuffer(serialized))
	protoPublicKeyset, err := reader.Read()
	if err != nil {
		t.Fatalf("reader.Read() err = %v, want nil", err)
	}
	handle3, err := keyset.NewHandleWithNoSecrets(protoPublicKeyset)
	if err != nil {
		t.Fatalf("keyset.NewHandleWithNoSecrets() err = %v, want nil", err)
	}

	if !proto.Equal(testkeyset.KeysetMaterial(handle), testkeyset.KeysetMaterial(handle3)) {
		t.Fatalf("keyset.NewHandleWithNoSecrets() = %v, want %v", handle3, handle)
	}
}

func TestNewHandleWithNoSecretsReturnsErrorIfInputIsNil(t *testing.T) {
	if _, err := keyset.NewHandleWithNoSecrets(nil); err == nil {
		t.Fatal("keyset.NewHandleWithNoSecrets(nil) err = nil, want error")
	}
}

func TestWriteWithNoSecretsFailsWithSymmetricSecretKey(t *testing.T) {
	// Create a keyset that contains a symmetric secret key.
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}
}

func TestReadWithNoSecretsFailsWithSymmetricSecretKey(t *testing.T) {
	// Create a keyset that contains a symmetric secret key.
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(aead.AES256GCMKeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	err = testkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("keyset.ReadWithNoSecrets() = nil, want error")
	}
}

func TestWriteWithNoSecretsFailsWithPrivateKey(t *testing.T) {
	// Create a keyset that contains a private key.
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)); err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}
}

func TestReadWithNoSecretsFailsWithPrivateKey(t *testing.T) {
	// Create a keyset that contains a private key.
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	err = testkeyset.Write(handle, keyset.NewBinaryWriter(buff))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)) err = %v, want nil", err)
	}
	serialized := buff.Bytes()

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("keyset.ReadWithNoSecrets() = nil, want error")
	}
}

func TestWriteAndReadWithNoSecretsFailsWithUnknownKeyMaterial(t *testing.T) {
	// Create a keyset that contains unknown key material.
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_UNKNOWN_KEYMATERIAL)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 1, tinkpb.OutputPrefixType_TINK)
	ks := testutil.NewKeyset(1, []*tinkpb.Keyset_Key{key})
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := proto.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}

	buff := &bytes.Buffer{}
	err = handle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff))
	if err == nil {
		t.Error("handle.WriteWithNoSecrets() = nil, want error")
	}

	_, err = keyset.ReadWithNoSecrets(keyset.NewBinaryReader(bytes.NewBuffer(serialized)))
	if err == nil {
		t.Error("handle.ReadWithNoSecrets() = nil, want error")
	}
}

func TestKeysetInfo(t *testing.T) {
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kh, err := keyset.NewHandle(kt)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	info := kh.KeysetInfo()
	if info.PrimaryKeyId != info.KeyInfo[0].KeyId {
		t.Errorf("Expected primary key id: %d, but got: %d", info.KeyInfo[0].KeyId, info.PrimaryKeyId)
	}
}

func TestPrimitivesWithRegistry(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) err = %v, want nil", template, err)
	}
	handleMAC, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New(%v) err = %v, want nil", handle, err)
	}

	ks := testkeyset.KeysetMaterial(handle)
	if len(ks.Key) != 1 {
		t.Fatalf("len(ks.Key) = %d, want 1", len(ks.Key))
	}
	keyDataPrimitive, err := registry.PrimitiveFromKeyData(ks.Key[0].KeyData)
	if err != nil {
		t.Fatalf("registry.PrimitiveFromKeyData(%v) err = %v, want nil", ks.Key[0].KeyData, err)
	}
	keyDataMAC, ok := keyDataPrimitive.(tink.MAC)
	if !ok {
		t.Fatal("registry.PrimitiveFromKeyData(keyData) is not of type tink.MAC")
	}

	plaintext := []byte("plaintext")
	handleMACTag, err := handleMAC.ComputeMAC(plaintext)
	if err != nil {
		t.Fatalf("handleMAC.ComputeMAC(%v) err = %v, want nil", plaintext, err)
	}
	if err = keyDataMAC.VerifyMAC(handleMACTag, plaintext); err != nil {
		t.Errorf("keyDataMAC.VerifyMAC(%v, %v) err = %v, want nil", handleMACTag, plaintext, err)
	}
	keyDataMACTag, err := keyDataMAC.ComputeMAC(plaintext)
	if err != nil {
		t.Fatalf("keyDataMAC.ComputeMAC(%v) err = %v, want nil", plaintext, err)
	}
	if err = handleMAC.VerifyMAC(keyDataMACTag, plaintext); err != nil {
		t.Errorf("handleMAC.VerifyMAC(%v, %v) err = %v, want nil", keyDataMACTag, plaintext, err)
	}
}

type testConfig struct{}

func (c *testConfig) PrimitiveFromKey(_ key.Key, _ internalapi.Token) (any, error) {
	return testPrimitive{}, nil
}

func TestPrimitivesWithConfig(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}
	primitives, err := handle.Primitives(keyset.WithConfig(&testConfig{}))
	if err != nil {
		t.Fatalf("handle.Primitives(keyset.WithConfig(&testConfig{})) err = %v, want nil", err)
	}
	if len(primitives.EntriesInKeysetOrder) != 1 {
		t.Fatalf("len(handle.Primitives()) = %d, want 1", len(primitives.EntriesInKeysetOrder))
	}
	if _, ok := (primitives.Primary.Primitive).(testPrimitive); !ok {
		t.Errorf("handle.Primitives().Primary = %v, want instance of `testPrimitive`", primitives.Primary.Primitive)
	}
}

func TestPrimitivesWithMultipleConfigs(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}
	_, err = handle.Primitives(keyset.WithConfig(&testConfig{}), keyset.WithConfig(&testConfig{}))
	if err == nil { // if NO error
		t.Error("handle.Primitives(keyset.WithConfig(&testConfig{}), keyset.WithConfig(&testConfig{})) err = nil, want error")
	}
}

type testKeyManager struct{}

type testPrimitive struct{}

func (km *testKeyManager) Primitive(_ []byte) (any, error)              { return testPrimitive{}, nil }
func (km *testKeyManager) NewKey(_ []byte) (proto.Message, error)       { return nil, nil }
func (km *testKeyManager) TypeURL() string                              { return mac.HMACSHA256Tag128KeyTemplate().TypeUrl }
func (km *testKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) { return nil, nil }
func (km *testKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == mac.HMACSHA256Tag128KeyTemplate().TypeUrl
}

func TestPrimitivesWithKeyManager(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) = %v, want nil", template, err)
	}

	// Verify that without providing a custom key manager we get a usual MAC.
	if _, err = mac.New(handle); err != nil {
		t.Fatalf("mac.New(%v) err = %v, want nil", handle, err)
	}

	// Verify that with the custom key manager provided we get the custom primitive.
	primitives, err := handle.PrimitivesWithKeyManager(&testKeyManager{})
	if err != nil {
		t.Fatalf("handle.PrimitivesWithKeyManager(testKeyManager) err = %v, want nil", err)
	}
	if len(primitives.EntriesInKeysetOrder) != 1 {
		t.Fatalf("len(handle.PrimitivesWithKeyManager()) = %d, want 1", len(primitives.EntriesInKeysetOrder))
	}
	if _, ok := (primitives.Primary.Primitive).(testPrimitive); !ok {
		t.Errorf("handle.PrimitivesWithKeyManager().Primary = %v, want instance of `testPrimitive`", primitives.Primary.Primitive)
	}
}

func TestLenWithOneKey(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle(%v) err = %v, want nil", template, err)
	}
	if handle.Len() != 1 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}
}

func TestLenWithMultipleKeys(t *testing.T) {
	ks := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(4, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		},
		PrimaryKeyId: 1,
	}
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(%v) err = %v, want nil", ks, err)
	}
	if handle.Len() != len(ks.Key) {
		t.Errorf("handle.Len() = %d, want %d", handle.Len(), len(ks.Key))
	}
}

func TestEntryReturnsCorrectKey(t *testing.T) {
	ks := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			testutil.NewDummyKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(4, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		},
		PrimaryKeyId: 2,
	}
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(%v) err = %v, want nil", ks, err)
	}

	for i := 0; i < handle.Len(); i++ {
		entry, err := handle.Entry(i)
		if err != nil {
			t.Errorf("handle.Entry(%d) err = %v, want nil", i, err)
		}
		if int(entry.KeyID()) != i {
			t.Errorf("entry.KeyID() = %v, want %v", entry.KeyID(), i)
		}
		if wantIsPrimary := i == 2; entry.IsPrimary() != wantIsPrimary {
			t.Errorf("entry.IsPrimary() = %v, want %v", entry.IsPrimary(), wantIsPrimary)
		}
		if entry.KeyStatus() != keyset.Enabled {
			t.Errorf("entry.KeyStatus() = %v, want Enabled", entry.KeyStatus())
		}
	}
}

func TestEntryFailsIfIndexOutOfRange(t *testing.T) {
	ks := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			testutil.NewDummyKey(4, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		},
		PrimaryKeyId: 1,
	}
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(%v) err = %v, want nil", ks, err)
	}
	_, err = handle.Entry(-1)
	if err == nil {
		t.Error("handle.Entry(-1) err = nil, want error")
	}
	_, err = handle.Entry(handle.Len())
	if err == nil {
		t.Errorf("handle.Entry(%d) err = nil, want error", handle.Len())
	}
}

func TestPrimaryReturnsPrimaryKey(t *testing.T) {
	primaryKey := testutil.NewDummyKey(2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK)
	ks := &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			testutil.NewDummyKey(1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
			primaryKey,
			testutil.NewDummyKey(3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		},
		PrimaryKeyId: 2,
	}
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(%v) err = %v, want nil", ks, err)
	}
	primaryEntry, err := handle.Primary()
	if err != nil {
		t.Fatalf("handle.Primary() err = %v, want nil", err)
	}
	if primaryEntry.KeyID() != 2 {
		t.Errorf("primaryEntry.KeyID() = %v, want 2", primaryEntry.KeyID())
	}
	if primaryEntry.KeyStatus() != keyset.Enabled {
		t.Errorf("primaryEntry.KeyStatus() = %v, want Enabled", primaryEntry.KeyStatus())
	}
	primaryProtoKey, ok := primaryEntry.Key().(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Fatalf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", primaryEntry.Key())
	}
	primaryProtoKeysetKey := protoserialization.ProtoKeysetKey(primaryProtoKey)
	if !proto.Equal(primaryProtoKeysetKey, primaryKey) {
		t.Errorf("primaryProtoKey.ProtoKeysetKey() = %v, want %v", primaryProtoKeysetKey, primaryKey)
	}
	// Check that is the same as Entry(1).
	entry, err := handle.Entry(1)
	if err != nil {
		t.Fatalf("handle.Entry(1) err = %v, want nil", err)
	}
	entryProtoKey, ok := entry.Key().(*protoserialization.FallbackProtoKey)
	if !ok {
		t.Fatalf("type mismatch: got %T, want *protoserialization.FallbackProtoKey", entry.Key())
	}
	entryProtoKeysetKey := protoserialization.ProtoKeysetKey(entryProtoKey)
	if !proto.Equal(entryProtoKeysetKey, primaryProtoKeysetKey) {
		t.Errorf("entryProtoKey.ProtoKeysetKey() = %v, want %v", entryProtoKeysetKey, primaryProtoKeysetKey)
	}
	if !proto.Equal(entryProtoKeysetKey, primaryProtoKeysetKey) {
		t.Errorf("proto.Equal(entryProtoKeysetKey, primaryProtoKeysetKey) = false, want true")
	}
}

func TestPrimaryIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			_, err := handle.Primary()
			if err != nil {
				t.Fatalf("handle.Primary() err = %v, want nil", err)
			}
		})
	}
}

func TestEntryIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			_, err := handle.Entry(0) // Index doesn't matter.
			if err != nil {
				t.Fatalf("handle.Entry() err = %v, want nil", err)
			}
		})
	}
}

func TestKeysetInfoIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			if handle.KeysetInfo() == nil {
				t.Fatalf("handle.KeysetInfo() == nul, want non-nil")
			}
		})
	}
}

func TestPrimitivesIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			_, err := handle.Primitives()
			if err != nil {
				t.Fatalf("handle.Primitives() err = %v, want nil", err)
			}
		})
	}
}

func TestPrimitivesWithKeyManagerIsThreadSafe(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	keysetManager := &testKeyManager{}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			_, err := handle.PrimitivesWithKeyManager(keysetManager)
			if err != nil {
				t.Fatalf("handle.PrimitivesWithKeyManager(keysetManager) err = %v, want nil", err)
			}
		})
	}
}

func TestPublicIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			_, err := handle.Public()
			if err != nil {
				t.Fatalf("handle.Public() err = %v, want nil", err)
			}
		})
	}
}

func TestWriteIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
			if err != nil {
				t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
			}
			buff := &bytes.Buffer{}
			err = handle.Write(keyset.NewBinaryWriter(buff), keysetEncryptionAead)
			if err != nil {
				t.Fatalf("handle.Write() err = %v, want nil", err)
			}
		})
	}
}

func TestWriteWithAssociatedDataIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	keysetEncryptionHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Errorf("keyset.NewHandle(aead.AES128GCMKeyTemplate()) err = %v, want nil", err)
	}
	associatedData := []byte{0x01, 0x02}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			buff := &bytes.Buffer{}
			keysetEncryptionAead, err := aead.New(keysetEncryptionHandle)
			if err != nil {
				t.Errorf("aead.New(keysetEncryptionHandle) err = %v, want nil", err)
			}
			if err := handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData); err != nil {
				t.Fatalf("handle.WriteWithAssociatedData(keyset.NewBinaryWriter(buff), keysetEncryptionAead, associatedData) err = %v, want nil", err)
			}
		})
	}
}

func TestWriteWithNoSecretsIsThreadSafe(t *testing.T) {
	template := signature.ECDSAP256KeyTemplate()
	manager := keyset.NewManager()
	// Add 10 keys. Last one is the primary.
	for i := 0; i < 10; i++ {
		keyID, err := manager.Add(template)
		if err != nil {
			t.Fatalf("manager.Add(template) err = %v, want nil", err)
		}
		if err = manager.SetPrimary(keyID); err != nil {
			t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
		}
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("manager.Public() err = %v, want nil", err)
	}
	for i := 0; i < 50; i++ {
		t.Run(fmt.Sprintf("entry %d", i), func(t *testing.T) {
			t.Parallel()
			buff := &bytes.Buffer{}
			if err := publicHandle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)); err != nil {
				t.Fatalf("publicHandle.WriteWithNoSecrets(keyset.NewBinaryWriter(buff)) err = %v, want nil", err)
			}
		})
	}
}
