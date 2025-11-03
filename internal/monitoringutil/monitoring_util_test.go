// Copyright 2022 Google LLC
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

package monitoringutil_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestKeysetInfoFromPrimitiveSetWithNilPrimitiveSetFails(t *testing.T) {
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet[any](nil); err == nil {
		t.Errorf("monitoringutil.KeysetInfoFromPrimitiveSet[any](nil) err = nil, want error")
	}
}

func validPrimitiveSet(t *testing.T) *primitiveset.PrimitiveSet[tink.AEAD] {
	t.Helper()
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	entry, err := kh.Primary()
	if err != nil {
		t.Fatalf("kh.Primary() err = %v, want nil", err)
	}
	ps := primitiveset.New[tink.AEAD]()
	ps.Add(&primitiveset.Entry[tink.AEAD]{
		KeyID:     1234567,
		Key:       entry.Key(),
		Primitive: &testutil.DummyAEAD{Name: "test"},
		IsPrimary: entry.IsPrimary(),
	})
	return ps
}

func TestBaselinePrimitiveSet(t *testing.T) {
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(validPrimitiveSet(t)); err != nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = %v, want nil", err)
	}
}

func TestKeysetInfoFromPrimitiveSetWithNoEntryFails(t *testing.T) {
	ps := validPrimitiveSet(t)
	ps.Entries = nil
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = nil, want error")
	}
}

func TestKeysetInfoFromPrimitiveSetWithNoPrimaryFails(t *testing.T) {
	ps := validPrimitiveSet(t)
	ps.Primary = nil
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = nil, want error")
	}
}

func TestKeysetInfoFromPrimitiveSet(t *testing.T) {
	km := keyset.NewManager()
	keyID1, err := km.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID1); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	keyID2, err := km.Add(aead.AES256GCMSIVNoPrefixKeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	keyID3, err := km.Add(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.Disable(keyID3); err != nil {
		t.Fatalf("km.Disable() err = %v, want nil", err)
	}
	if err := km.SetAnnotations(map[string]string{"foo": "bar", "zoo": "far"}); err != nil {
		t.Fatalf("km.SetAnnotations() err = %v, want nil", err)
	}
	h, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	ps, err := keyset.Primitives[tink.AEAD](h, &registryconfig.RegistryConfig{}, internalapi.Token{})
	if err != nil {
		t.Fatalf("primitiveset.NewFromKeysetHandle() err = %v, want nil", err)
	}

	want := &monitoring.KeysetInfo{
		PrimaryKeyID: keyID1,
		Annotations: map[string]string{
			"foo": "bar",
			"zoo": "far",
		},
		Entries: []*monitoring.Entry{
			{
				KeyID:     keyID1,
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesGcmKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyID2,
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesGcmSivKey",
				KeyPrefix: "RAW",
			},
		},
	}
	got, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		t.Fatalf("KeysetInfoFromPrimitiveSet() err = %v, want nil", err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestMonitoringKeysetInfoFromKeysetInfo_Nil(t *testing.T) {
	if _, err := monitoringutil.MonitoringKeysetInfoFromKeysetInfo(nil, nil); err != nil {
		t.Errorf("MonitoringKeysetInfoFromKeysetInfo() err = %v, want nil", err)
	}
}

func TestMonitoringKeysetInfoFromKeysetInfo(t *testing.T) {
	km := keyset.NewManager()
	keyID1, err := km.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID1); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	keyID2, err := km.Add(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	if err := km.Disable(keyID2); err != nil {
		t.Fatalf("km.Disable() err = %v, want nil", err)
	}
	keyID3, err := km.Add(aead.XAES256GCM192BitNonceNoPrefixKeyTemplate())
	if err != nil {
		t.Fatalf("km.Add() err = %v, want nil", err)
	}
	h, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	info := h.KeysetInfo()
	annotations := map[string]string{
		"foo": "bar",
		"zoo": "far",
	}
	got, err := monitoringutil.MonitoringKeysetInfoFromKeysetInfo(info, annotations)
	if err != nil {
		t.Fatalf("MonitoringKeysetInfoFromKeysetInfo() err = %v, want nil", err)
	}

	want := &monitoring.KeysetInfo{
		PrimaryKeyID: keyID1,
		Annotations: map[string]string{
			"foo": "bar",
			"zoo": "far",
		},
		Entries: []*monitoring.Entry{
			{
				KeyID:     keyID1,
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesGcmKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyID2,
				Status:    monitoring.Disabled,
				KeyType:   "tink.AesCtrHmacAeadKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyID3,
				Status:    monitoring.Enabled,
				KeyType:   "tink.XAesGcmKey",
				KeyPrefix: "RAW",
			},
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}
