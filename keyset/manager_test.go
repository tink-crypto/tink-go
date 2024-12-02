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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	ErrParamtersSerialization = errors.New("parameters serialization failed")
)

func TestKeysetManagerBasic(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	keyID, err := ksm.Add(kt)
	if err != nil {
		t.Errorf("cannot add key: %s", err)
	}
	err = ksm.SetPrimary(keyID)
	if err != nil {
		t.Errorf("cannot set primary key: %s", err)
	}
	h, err := ksm.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks := testkeyset.KeysetMaterial(h)
	if len(ks.Key) != 1 {
		t.Fatal("expect the number of keys in the keyset is 1")
	}
	if ks.Key[0].KeyId != ks.PrimaryKeyId ||
		ks.Key[0].KeyData.TypeUrl != testutil.HMACTypeURL ||
		ks.Key[0].Status != tinkpb.KeyStatusType_ENABLED ||
		ks.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("incorrect key information: %s", ks.Key[0])
	}
}

func TestKeysetManagerExistingKeyset(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	keyID1, err := ksm1.Add(kt)
	if err != nil {
		t.Errorf("cannot add key: %s", err)
	}
	err = ksm1.SetPrimary(keyID1)
	if err != nil {
		t.Errorf("cannot set primary key: %s", err)
	}
	h1, err := ksm1.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks1 := testkeyset.KeysetMaterial(h1)

	ksm2 := keyset.NewManagerFromHandle(h1)
	keyID2, err := ksm2.Add(kt)
	if err != nil {
		t.Errorf("cannot add key: %s", err)
	}
	err = ksm2.SetPrimary(keyID2)
	if err != nil {
		t.Errorf("cannot set primary key: %s", err)
	}
	h2, err := ksm2.Handle()
	if err != nil {
		t.Errorf("cannot get keyset handle: %s", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)

	if len(ks2.Key) != 2 {
		t.Errorf("expect the number of keys to be 2, got %d", len(ks2.Key))
	}
	if ks1.Key[0].String() != ks2.Key[0].String() {
		t.Errorf("expect the first key in two keysets to be the same")
	}
	if ks2.Key[1].KeyId != ks2.PrimaryKeyId {
		t.Errorf("expect the second key to be primary")
	}
}

func TestKeysetManagerNewManagerFromHandleMakesACopy(t *testing.T) {
	// Create a keyset that contains a single HmacKey.
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	keyID1, err := ksm1.Add(kt)
	if err != nil {
		t.Errorf("ksm1.Add(kt) err = %q, want nil", err)
	}
	err = ksm1.SetPrimary(keyID1)
	if err != nil {
		t.Errorf("ksm1.SetPrimary(%v) err = %q, want nil", keyID1, err)
	}
	h1, err := ksm1.Handle()
	if err != nil {
		t.Errorf("ksm1.Handle() err = %q, want nil", err)
	}
	if h1.Len() != 1 {
		t.Errorf("h1.Len() = %d, want 1", h1.Len())
	}

	ksm2 := keyset.NewManagerFromHandle(h1)
	keyID2, err := ksm2.Add(kt)
	if err != nil {
		t.Errorf("ksm2.Add(kt) err = %q, want nil", err)
	}
	err = ksm2.SetPrimary(keyID2)
	if err != nil {
		t.Errorf("ksm2.SetPrimary(%v) err = %q, want nil", keyID2, err)
	}
	h2, err := ksm2.Handle()
	if err != nil {
		t.Errorf("ksm2.Handle() err = %q, want nil", err)
	}
	if h2.Len() != 2 {
		t.Errorf("h2.Len() = %d, want 2", h2.Len())
	}

	// Make sure no changes were made to the original handle.
	if h1.Len() == h2.Len() {
		t.Errorf("h1.Len() == h2.Len(), want different")
	}
}

func TestKeysetManagerAddSetPrimaryHandle(t *testing.T) {
	// Test a full keyset manager cycle: Add, SetPrimary, Handle.
	ksm := keyset.NewManager()
	keyID, err := ksm.Add(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Errorf("ksm.Add(mac.HMACSHA256Tag128KeyTemplate()) err = %q, want nil", err)
	}
	err = ksm.SetPrimary(keyID)
	if err != nil {
		t.Errorf("ksm.SetPrimary(%v) err = %q, want nil", keyID, err)
	}
	h1, err := ksm.Handle()
	if err != nil {
		t.Errorf("ksm.Handle() err = %q, want nil", err)
	}
	info := h1.KeysetInfo()
	if len(info.KeyInfo) != 1 {
		t.Errorf("len(h1.KeysetInfo()) = %d, want 1", len(info.KeyInfo))
	}
	if info.KeyInfo[0].GetKeyId() != keyID {
		t.Errorf("info.KeyInfo[0].GetKeyId() = %d, want %d", info.KeyInfo[0].GetKeyId(), keyID)
	}
	ks1 := testkeyset.KeysetMaterial(h1)
	err = keyset.Validate(ks1)
	if err != nil {
		t.Errorf("keyset.Validate(ks1) err = %q, want nil", err)
	}
}

func TestKeysetManagerAdd(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	keyID, err := ksm1.Add(kt)
	if err != nil {
		t.Errorf("ksm1.Add(kt) err = %q, want nil", err)
	}
	err = ksm1.SetPrimary(keyID)
	if err != nil {
		t.Errorf("ksm1.SetPrimary(keyID) err = %q, want nil", err)
	}
	h, err := ksm1.Handle()
	if err != nil {
		t.Errorf("ksm1.Handle() err = %q, want nil", err)
	}
	if h.Len() != 1 {
		t.Errorf("h.Len() = %d, want 1", h.Len())
	}
	entry, err := h.Entry(0)
	if err != nil {
		t.Errorf("h.Entry(0) err = %q, want nil", err)
	}
	if entry.KeyID() != keyID {
		t.Errorf("entry.KeyID() = %d, want %d", entry.KeyID(), keyID)
	}
	if entry.KeyStatus() != keyset.Enabled {
		t.Errorf("entry.KeyStatus() = %s, want %s", entry.KeyStatus().String(), keyset.Enabled.String())
	}
}

func TestKeysetManagerAddWithNilKeysetTemplateFails(t *testing.T) {
	// ops with nil template should fail
	ksm1 := keyset.NewManager()
	_, err := ksm1.Add(nil)
	if err == nil {
		t.Errorf("ksm1.Add succeeded, but want error")
	}
}

func TestKeysetManagerAddWithInvalidTypeUrlFails(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := &tinkpb.KeyTemplate{
		TypeUrl:          "invalid type",
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
	_, err := ksm1.Add(kt)
	if err == nil {
		t.Errorf("ksm1.Add succeeded, want error")
	}
}

func TestKeysetManagerAddWithUnknownOutputPrefixTypeFails(t *testing.T) {
	ksm1 := keyset.NewManager()
	kt := mac.HMACSHA256Tag128KeyTemplate()
	kt.OutputPrefixType = tinkpb.OutputPrefixType_UNKNOWN_PREFIX
	_, err := ksm1.Add(kt)
	if err == nil {
		t.Errorf("ksm1.Add(kt) where kt has an unknown prefix succeeded, want error")
	}
}

func TestKeysetManagerEnable(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	keyID1 := uint32(42)
	key1 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DISABLED, keyID1, tinkpb.OutputPrefixType_TINK)
	keyID2 := uint32(43)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID2, tinkpb.OutputPrefixType_TINK)
	ks1 := &tinkpb.Keyset{
		Key:          []*tinkpb.Keyset_Key{key1, key2},
		PrimaryKeyId: keyID2,
	}
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}

	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err = ksm1.Enable(keyID1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	h2, err := ksm1.Handle()
	if err != nil {
		t.Errorf("ksm1.Handle() err = %q, want nil", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 2 {
		t.Fatalf("Expected only 2 keys, got %d", len(ks2.Key))
	}
	if ks2.Key[0].KeyId != keyID1 {
		t.Errorf("Expected keyID %d, got %d", keyID1, ks2.Key[0].KeyId)
	}
	if ks2.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("Expected key to be enabled, but got %s", ks2.Key[0].Status.String())
	}
}

func TestKeysetManagerEnableWithDestroyed(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	keyID1 := uint32(42)
	key1 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, keyID1, tinkpb.OutputPrefixType_TINK)
	keyID2 := uint32(43)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID2, tinkpb.OutputPrefixType_TINK)
	ks1 := &tinkpb.Keyset{
		Key:          []*tinkpb.Keyset_Key{key1, key2},
		PrimaryKeyId: keyID2,
	}
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err = ksm1.Enable(keyID1)
	if err == nil {
		t.Errorf("ksm1.Enable where key was destroyed succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot enable") {
		t.Errorf("Expected 'cannot enable' message, got %s", err)
	}
}

func TestKeysetManagerEnableWithMissingKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := &tinkpb.Keyset{
		Key:          []*tinkpb.Keyset_Key{key},
		PrimaryKeyId: keyID,
	}
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// enable key
	err = ksm1.Enable(uint32(43))
	if err == nil {
		t.Errorf("ksm1.Enable where key doesn't exist succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimary(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err = ksm1.SetPrimary(newKeyID)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	h2, err := ksm1.Handle()
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 2 {
		t.Errorf("Expected two keys, got %d", len(ks2.Key))
	}
	if ks2.PrimaryKeyId != newKeyID {
		t.Errorf("Expected new key to be primary, got %d", ks2.PrimaryKeyId)
	}
}

func TestKeysetManagerSetPrimaryWithDisabledKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create a disabled key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DISABLED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err = ksm1.SetPrimary(newKeyID)
	if err == nil {
		t.Errorf("ksm1.SetPrimary on disabled key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("Expected 'not enabled' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimaryWithDestroyedKey(t *testing.T) {
	keyID := uint32(42)
	newKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	// create a destroyed key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, newKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err = ksm1.SetPrimary(newKeyID)
	if err == nil {
		t.Errorf("ksm1.SetPrimary on destroyed key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("Expected 'not enabled' message, got %s", err)
	}
}

func TestKeysetManagerSetPrimaryWithMissingKey(t *testing.T) {
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 42, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 43, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(42, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// set primary key
	err = ksm1.SetPrimary(uint32(44))
	if err == nil {
		t.Errorf("ksm1.SetPrimary on missing key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerDisable(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err = ksm1.Disable(otherKeyID)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	h2, err := ksm1.Handle()
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)
	if ks2.PrimaryKeyId != primaryKeyID {
		t.Errorf("Expected same key to be primary, got %d", ks2.PrimaryKeyId)
	}
	if len(ks2.Key) != 2 {
		t.Errorf("Expected two keys, got %d", len(ks2.Key))
		t.FailNow()
	}
	if ks2.Key[1].Status != tinkpb.KeyStatusType_DISABLED {
		t.Errorf("Expected key to be disabled, got %s", ks2.Key[1].Status.String())
	}
}

func TestKeysetManagerDisableWithPrimaryKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err = ksm1.Disable(primaryKeyID)
	if err == nil {
		t.Errorf("ksm1.Disable on primary key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot disable the primary key") {
		t.Errorf("Expected 'cannot disable the primary key' message, got %s", err)
	}
	h2, err := ksm1.Handle()
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)
	if ks2.PrimaryKeyId != primaryKeyID {
		t.Errorf("Expected same key to be primary, got %d", ks2.PrimaryKeyId)
	}
}

func TestKeysetManagerDisableWithDestroyedKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	// destroyed key
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_DESTROYED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err = ksm1.Disable(otherKeyID)
	if err == nil {
		t.Errorf("ksm1.Disable on destroyed key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "cannot disable") {
		t.Errorf("Expected 'cannot disable' message, got %s", err)
	}
}

func TestKeysetManagerDisableWithMissingKey(t *testing.T) {
	primaryKeyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, primaryKeyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(primaryKeyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// disable key
	err = ksm1.Disable(uint32(44))
	if err == nil {
		t.Errorf("ksm1.Disable on missing key succeeded, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' message, got %s", err)
	}
}

func TestKeysetManagerDelete(t *testing.T) {
	keyID := uint32(42)
	otherKeyID := uint32(43)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	key2 := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, otherKeyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key, key2})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err = ksm1.Delete(otherKeyID)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	h2, err := ksm1.Handle()
	if err != nil {
		t.Fatalf("ksm1.Handle() err = %q, want nil", err)
	}
	ks2 := testkeyset.KeysetMaterial(h2)
	if len(ks2.Key) != 1 {
		t.Fatalf("Expected only one key but got %d", len(ks2.Key))
	}
	if ks2.Key[0].KeyId != ks2.PrimaryKeyId || ks2.Key[0].KeyId != keyID {
		t.Errorf("Expected keyID %d to be present but got %d", keyID, ks2.Key[0].KeyId)
	}
	if ks2.Key[0].Status != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("Expected key to be enabled but got %s", ks2.Key[0].Status.String())
	}
}

func TestKeysetManagerDeleteWithPrimaryKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err = ksm1.Delete(keyID)
	if err == nil {
		t.Errorf("ksm1.Delete succeeded but expected error")
	}
	if !strings.Contains(err.Error(), "primary key") {
		t.Errorf("Expected 'primary key' message but got %s", err)
	}
}

func TestKeysetManagerDeleteWithMissingKey(t *testing.T) {
	keyID := uint32(42)
	keyData := testutil.NewKeyData("some type url", []byte{0}, tinkpb.KeyData_SYMMETRIC)
	key := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
	ks1 := testutil.NewKeyset(keyID, []*tinkpb.Keyset_Key{key})
	h1, err := testkeyset.NewHandle(ks1)
	if err != nil {
		t.Errorf("Expected no error but got error %s", err)
	}
	ksm1 := keyset.NewManagerFromHandle(h1)
	// delete key
	err = ksm1.Delete(uint32(43))
	if err == nil {
		t.Errorf("ksm1.Delete succeeded but expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' message but got %s", err)
	}
}

func TestKeysetManagerWithEmptyManager(t *testing.T) {
	// all ops with empty manager should fail
	ksm1 := &keyset.Manager{}
	_, err := ksm1.Add(mac.HMACSHA256Tag128KeyTemplate())
	if err == nil {
		t.Errorf("ksm1.Add succeeded on empty manager, want error")
	}
	err = ksm1.SetPrimary(0)
	if err == nil {
		t.Errorf("ksm1.SetPrimary succeeded on empty manager, want error")
	}
	err = ksm1.Enable(0)
	if err == nil {
		t.Errorf("ksm1.Enable succeeded on empty manager, want error")
	}
	err = ksm1.Delete(0)
	if err == nil {
		t.Errorf("ksm1.Delete succeeded on empty manager, want error")
	}
	err = ksm1.Disable(0)
	if err == nil {
		t.Errorf("ksm1.Disable succeeded on empty manager, want error")
	}
}

func TestKeysetManagerHandleMakesACopyOfTheKeyset(t *testing.T) {
	manager := keyset.NewManager()
	template := mac.HMACSHA256Tag128KeyTemplate()
	keyID, err := manager.Add(template)
	if err != nil {
		t.Fatalf("manager.Add(template) err = %q, want nil", err)
	}
	err = manager.SetPrimary(keyID)
	if err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %q, want nil", keyID, err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %q, want nil", err)
	}
	if handle.Len() != 1 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}
	// Continue adding keys to the manager.
	_, err = manager.Add(template)
	if err != nil {
		t.Fatalf("manager.Add(template) err = %q, want nil", err)
	}
	if handle.Len() != 1 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}
	anotherHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %q, want nil", err)
	}
	if anotherHandle.Len() != 2 {
		t.Errorf("anotherHandle.Len() = %d, want 2", anotherHandle.Len())
	}
}

type testParameters struct {
	hasIDRequirement bool
}

func (p *testParameters) HasIDRequirement() bool { return p.hasIDRequirement }
func (p *testParameters) Equal(params key.Parameters) bool {
	_, ok := params.(*testParameters)
	return ok && p.hasIDRequirement == params.HasIDRequirement()
}

var _ key.Parameters = (*testParameters)(nil)

type testKey struct {
	params testParameters
	id     uint32
}

func (k *testKey) IDRequirement() (id uint32, required bool) {
	return k.id, k.Parameters().HasIDRequirement()
}
func (k *testKey) Parameters() key.Parameters { return &k.params }
func (k *testKey) Equal(other key.Key) bool {
	thisKeyID, Required := k.IDRequirement()
	otherkeyID, otherKeyRequired := other.IDRequirement()
	return thisKeyID == otherkeyID &&
		Required == otherKeyRequired &&
		k.Parameters().Equal(other.Parameters())
}

var _ key.Key = (*testKey)(nil)

type testKeySerializer struct{}

func (s *testKeySerializer) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	actualKey, ok := key.(*testKey)
	if !ok {
		return nil, fmt.Errorf("testKeySerializer.SerializeKey: key is not a testKey")
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         "test_type_url",
		Value:           []byte{0},
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	return protoserialization.NewKeySerialization(keyData, tinkpb.OutputPrefixType_TINK, actualKey.id)
}

func TestKeysetManagerAddKeySucceeds(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	if err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %q, want nil", err)
	}

	manager := keyset.NewManager()
	keyID1, err := manager.AddKey(&testKey{
		params: testParameters{hasIDRequirement: true},
		id:     1,
	})
	if err != nil {
		t.Fatalf("manager.AddKey() err = %q, want nil", err)
	}
	if keyID1 != 1 {
		t.Errorf("keyID1 = %d, want 1", keyID1)
	}
	keyID2, err := manager.AddKey(
		&testKey{
			params: testParameters{hasIDRequirement: false},
			id:     2,
		})
	if err != nil {
		t.Fatalf("manager.AddKey() err = %q, want nil", err)
	}

	if err := manager.SetPrimary(keyID1); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %q, want nil", keyID1, err)
	}

	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %q, want nil", err)
	}
	if handle.Len() != 2 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}

	keysetProto := testkeyset.KeysetMaterial(handle)
	if keysetProto.Key[0].KeyId != keyID1 {
		t.Errorf("keysetProto.Key[0].KeyId = %d, want %v", keysetProto.Key[0].KeyId, keyID1)
	}
	if keysetProto.Key[0].GetStatus() != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("keysetProto.Key[0].GetStatus() = %v, want %v", keysetProto.Key[0].GetStatus(), tinkpb.KeyStatusType_ENABLED)
	}
	if keysetProto.Key[1].KeyId != keyID2 {
		t.Errorf("keysetProto.Key[0].KeyId = %d, want %v", keysetProto.Key[1].KeyId, keyID2)
	}
	if keysetProto.Key[1].GetStatus() != tinkpb.KeyStatusType_ENABLED {
		t.Errorf("keysetProto.Key[1].GetStatus() = %v, want %v", keysetProto.Key[1].GetStatus(), tinkpb.KeyStatusType_DISABLED)
	}
}

func TestKeysetManagerAddKeyFromExistingKeyset(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	if err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %q, want nil", err)
	}

	// Create a keyset that contains a single HmacKey.
	manager := keyset.NewManager()
	template := mac.HMACSHA256Tag128KeyTemplate()
	keyID1, err := manager.Add(template)
	if err != nil {
		t.Errorf("manager.Add(template) err = %q, want nil", err)
	}
	err = manager.SetPrimary(keyID1)
	if err != nil {
		t.Errorf("manager.SetPrimary(%v) err = %q, want nil", keyID1, err)
	}
	keyID2, err := manager.AddKey(&testKey{
		params: testParameters{hasIDRequirement: true},
		id:     1,
	})
	if err != nil {
		t.Fatalf("manager.AddKey() err = %q, want nil", err)
	}
	if keyID2 != 1 {
		t.Errorf("keyID2 = %d, want 1", keyID2)
	}
	keyID3, err := manager.AddKey(
		&testKey{
			params: testParameters{hasIDRequirement: false},
			id:     2,
		})
	if err != nil {
		t.Fatalf("manager.AddKey() err = %q, want nil", err)
	}
	// The ID should be randomly generated and different from the existing key IDs.
	if keyID3 == keyID1 || keyID3 == keyID2 {
		t.Errorf("(%v == %v || %v == %v) == true, want false", keyID3, keyID1, keyID3, keyID2)
	}

	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %q, want nil", err)
	}
	if handle.Len() != 3 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}
	keysetProto := testkeyset.KeysetMaterial(handle)
	if keysetProto.GetPrimaryKeyId() != keyID1 {
		t.Errorf("keysetProto.GetPrimaryKeyId() = %d, want %v", keysetProto.GetPrimaryKeyId(), keyID1)
	}
}

func TestKeysetManagerAddKeyFailsIfKeyIsNull(t *testing.T) {
	manager := keyset.NewManager()
	_, err := manager.AddKey(nil)
	if err == nil {
		t.Errorf("manager.AddKey() err = nil, want err")
	}
}

func TestKeysetManagerAddKeyFailsIfNoSerializerIsAvailable(t *testing.T) {
	manager := keyset.NewManager()
	_, err := manager.AddKey(&testKey{
		params: testParameters{hasIDRequirement: true},
		id:     1,
	})
	if err == nil {
		t.Errorf("manager.AddKey() err = nil, want err")
	}
}

func TestKeysetManagerAddKeyFailsIfKeyHasIDRequirementAndIDAlreadyInUse(t *testing.T) {
	defer protoserialization.UnregisterKeySerializer[*testKey]()
	if err := protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer[*testKey](&testKeySerializer{}) err = %q, want nil", err)
	}

	manager := keyset.NewManager()
	keyID, err := manager.AddKey(&testKey{
		params: testParameters{hasIDRequirement: true},
		id:     1,
	})
	if err != nil {
		t.Fatalf("manager.AddKey() err = %q, want nil", err)
	}
	if keyID != 1 {
		t.Errorf("keyID = %d, want 1", keyID)
	}

	_, err = manager.AddKey(&testKey{
		params: testParameters{hasIDRequirement: true},
		id:     1,
	})
	if err == nil {
		t.Errorf("manager.AddKey() err = nil, want err")
	}
}

func TestKeysetManagerAddNewKeyFromParametersFailsIfNilParameters(t *testing.T) {
	manager := keyset.NewManager()
	if _, err := manager.AddNewKeyFromParameters(nil); err == nil {
		t.Errorf("manager.AddKeyFromParameters(nil) err = nil, want error")
	}
}

type testParams struct {
	hasIDRequirement bool
}

func (p *testParams) HasIDRequirement() bool { return p.hasIDRequirement }
func (p *testParams) Equal(params key.Parameters) bool {
	_, ok := params.(*testParams)
	return ok && p.hasIDRequirement == params.HasIDRequirement()
}

var _ key.Parameters = (*testParams)(nil)

type alwaysFailingParametersSerializer struct{}

func (s *alwaysFailingParametersSerializer) Serialize(params key.Parameters) (*tinkpb.KeyTemplate, error) {
	return nil, ErrParamtersSerialization
}

func TestKeysetManagerAddNewKeyFromParametersFailsIfSerializerFails(t *testing.T) {
	if err := protoserialization.RegisterParametersSerializer[*testParams](&alwaysFailingParametersSerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterParametersSerializer[*testParams](&alwaysFailingParametersSerializer{}) err = %q, want nil", err)
	}
	defer protoserialization.ClearParametersSerializers()

	manager := keyset.NewManager()
	params := &testParams{hasIDRequirement: true}

	_, err := manager.AddNewKeyFromParameters(params)
	if err == nil {
		t.Errorf("manager.AddKeyFromParameters(params) err = nil, want error")
	}
}

type testParametersSerializer struct{}

func (s *testParametersSerializer) Serialize(params key.Parameters) (*tinkpb.KeyTemplate, error) {
	return mac.HMACSHA256Tag128KeyTemplate(), nil
}

func TestKeysetManagerAddNewKeyFromParametersWorks(t *testing.T) {
	if err := protoserialization.RegisterParametersSerializer[*testParams](&testParametersSerializer{}); err != nil {
		t.Fatalf("protoserialization.RegisterParametersSerializer[*testParams](&testParametersSerializer{}) err = %q, want nil", err)
	}
	defer protoserialization.ClearParametersSerializers()
	manager := keyset.NewManager()
	params := &testParams{hasIDRequirement: true}
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Errorf("manager.AddKeyFromParameters(params) err = %v, want nil", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Errorf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %q, want nil", err)
	}
	if handle.Len() != 1 {
		t.Errorf("handle.Len() = %d, want 1", handle.Len())
	}

	// Make sure we can get and use a MAC primitive from the handle.
	primitive, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New(handle) err = %q, want nil", err)
	}
	message := []byte("message")
	tag, err := primitive.ComputeMAC(message)
	if err != nil {
		t.Errorf("primitive.ComputeMAC(message) err = %q, want nil", err)
	}
	if err := primitive.VerifyMAC(tag, message); err != nil {
		t.Errorf("primitive.VerifyMAC(message, mac) err = %q, want nil", err)
	}
}
