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

package hybrid_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"

	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestHybridFactoryTest(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	ht := commonpb.HashType_SHA256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryDek := aead.AES128CTRHMACSHA256KeyTemplate()
	rawDek := aead.AES128CTRHMACSHA256KeyTemplate()
	primarySalt := []byte("some salt")
	rawSalt := []byte("other salt")

	primaryPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, primaryPtFmt, primaryDek, primarySalt)
	if err != nil {
		t.Fatalf("testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, primaryPtFmt, primaryDek, primarySalt) err = %v, want nil", err)
	}
	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	if err != nil {
		t.Fatalf("proto.Marshal(primaryPrivProto) err = %v, want nil", err)
	}

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(testutil.EciesAeadHkdfPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt)
	if err != nil {
		t.Fatalf("testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt) err = %v, want nil", err)
	}
	sRawPriv, err := proto.Marshal(rawPrivProto)
	if err != nil {
		t.Fatalf("proto.Marshal(rawPrivProto) err = %v, want nil", err)
	}
	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(testutil.EciesAeadHkdfPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle(privKeyset) err = %v, want nil", err)
	}

	khPub, err := khPriv.Public()
	if err != nil {
		t.Fatalf("khPriv.Public() err = %v, want nil", err)
	}

	e, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt(khPub) err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt(khPriv) err = %v, want nil", err)
	}

	for i := 0; i < 1000; i++ {
		pt := random.GetRandomBytes(20)
		ci := random.GetRandomBytes(20)
		ct, err := e.Encrypt(pt, ci)
		if err != nil {
			t.Fatalf("e.Encrypt(pt, ci) err = %v, want nil", err)
		}
		gotpt, err := d.Decrypt(ct, ci)
		if err != nil {
			t.Fatalf("d.Decrypt(ct, ci) err = %v, want nil", err)
		}
		if !bytes.Equal(pt, gotpt) {
			t.Errorf("got plaintext %q, want %q", gotpt, pt)
		}
	}
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(signature.ECDSAP256KeyTemplate()) err = %v, want nil", err)
	}

	_, err = hybrid.NewHybridEncrypt(wrongKH)
	if err == nil {
		t.Error("hybrid.NewHybridEncrypt(wrongKH) err = nil, want not nil")
	}

	_, err = hybrid.NewHybridDecrypt(wrongKH)
	if err == nil {
		t.Error("hybrid.NewHybridDecrypt(wrongKH) err = nil, want not nil")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate()) err = %v, want nil", err)
	}

	goodPublicKH, err := goodKH.Public()
	if err != nil {
		t.Fatalf("goodKH.Public() err = %v, want nil", err)
	}
	_, err = hybrid.NewHybridEncrypt(goodPublicKH)
	if err != nil {
		t.Errorf("hybrid.NewHybridEncrypt(goodPublicKH) err = %v, want nil", err)
	}

	_, err = hybrid.NewHybridDecrypt(goodKH)
	if err != nil {
		t.Errorf("hybrid.NewHybridDecrypt(goodKH) err = %v, want nil", err)
	}
}

func TestPrimitiveFactoryFailsWhenHandleIsEmpty(t *testing.T) {
	handle := &keyset.Handle{}
	if _, err := hybrid.NewHybridEncrypt(handle); err == nil {
		t.Errorf("NewHybridEncrypt(handle) err = nil, want not nil")
	}
	if _, err := hybrid.NewHybridDecrypt(handle); err == nil {
		t.Errorf("NewHybridDecrypt(handle) err = nil, want not nil")
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsLogsEncryptAndDecryptWithPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsLogsEncryptAndDecryptWithoutPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Raw_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "RAW",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "RAW",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    pubHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryWithMonitoringWithMultipleKeysLogsEncryptionDecryption(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	templates := []*tinkpb.KeyTemplate{
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template(),
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Raw_Key_Template(),
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Key_Template(),
		hybrid.ECIESHKDFAES128GCMKeyTemplate(),
	}
	keyIDs := make([]uint32, 4, 4)
	var err error
	for i, tm := range templates {
		keyIDs[i], err = manager.Add(tm)
		if err != nil {
			t.Fatalf("manager.Add() err = %v, want nil", err)
		}
	}
	if err := manager.SetPrimary(keyIDs[1]); err != nil {
		t.Fatalf("manager.SetPrimary(%d) err = %v, want nil", keyIDs[1], err)
	}
	if err := manager.Disable(keyIDs[0]); err != nil {
		t.Fatalf("manager.Disable(%d) err = %v, want nil", keyIDs[0], err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	wantEncryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     pubHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     keyIDs[2],
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePublicKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[3],
				Status:    monitoring.Enabled,
				KeyType:   "tink.EciesAeadHkdfPublicKey",
				KeyPrefix: "TINK",
			},
		},
	}
	wantDecryptKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: privHandle.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     keyIDs[2],
				Status:    monitoring.Enabled,
				KeyType:   "tink.HpkePrivateKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[3],
				Status:    monitoring.Enabled,
				KeyType:   "tink.EciesAeadHkdfPrivateKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("hybrid_encrypt", "encrypt", wantEncryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("hybrid_decrypt", "decrypt", wantDecryptKeysetInfo),
			KeyID:    privHandle.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
		},
	}
	// sort by keyID to avoid non deterministic order.
	entryLessFunc := func(a, b *monitoring.Entry) bool {
		return a.KeyID < b.KeyID
	}
	if diff := cmp.Diff(want, got, cmpopts.SortSlices(entryLessFunc)); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsEncryptFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	buff.Reset()

	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	pubHandle, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("NewHybridDecrypt() err = %v, want nil", err)
	}

	ct, err := e.Encrypt([]byte("plaintext"), []byte("info"))
	if err != nil {
		t.Fatalf("Encrypt() err = nil, want non-nil")
	}
	if _, err := d.Decrypt(ct, []byte("wrong info")); err == nil {
		t.Fatalf("Decrypt() err = nil, want non-nil")
	}

	got := client.Failures()
	primaryKeyID := privHandle.KeysetInfo().GetPrimaryKeyId()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"hybrid_decrypt",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					primaryKeyID,
					[]*monitoring.Entry{
						{
							KeyID:     primaryKeyID,
							Status:    monitoring.Enabled,
							KeyType:   "tink.HpkePrivateKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsDecryptFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	privHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	if _, err := e.Decrypt([]byte("invalid_data"), nil); err == nil {
		t.Fatalf("e.Decrypt() err = nil, want non-nil error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"hybrid_decrypt",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					privHandle.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     privHandle.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.HpkePrivateKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryEncryptDecryptWithoutAnnotationsDoesNotMonitor(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	privHandle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}
	e, err := hybrid.NewHybridEncrypt(pubHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	d, err := hybrid.NewHybridDecrypt(privHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}
	data := []byte("some_secret_piece_of_data")
	aad := []byte("some_non_secret_piece_of_data")
	ct, err := e.Encrypt(data, aad)
	if err != nil {
		t.Fatalf("e.Encrypt() err = %v, want nil", err)
	}
	if _, err := d.Decrypt(ct, aad); err != nil {
		t.Fatalf("d.Decrypt() err = %v, want nil", err)
	}
	if len(client.Events()) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(client.Events()))
	}
	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
}

// Since the HybridEncrypt interface is a subset of the AEAD interface, verify
// that a HybridEncrypt primitive cannot be obtained from a keyset handle
// containing an AEAD key.
func TestEncryptFactoryFailsOnAEADHandle(t *testing.T) {
	handle, err := keyset.NewHandle(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("keyset.NewHandle gives err = '%v', want nil", err)
	}
	pub, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public gives err = '%v', want nil", err)
	}
	manager := keyset.NewManagerFromHandle(pub)
	_, err = manager.Add(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	mixedHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}
	if _, err := hybrid.NewHybridEncrypt(mixedHandle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}

// Similar to the above but for HybridDecrypt.
func TestDecryptFactoryFailsOnAEADHandle(t *testing.T) {
	manager := keyset.NewManager()
	id, err := manager.Add(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	err = manager.SetPrimary(id)
	if err != nil {
		t.Fatalf("manager.SetPrimary gives err = '%v', want nil", err)
	}
	_, err = manager.Add(hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_Key_Template())
	if err != nil {
		t.Fatalf("manager.Add gives err = '%v', want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle gives err = '%v', want nil", err)
	}

	if _, err := hybrid.NewHybridDecrypt(handle); err == nil {
		t.Error("hybrid.NewHybridDecrypt err = nil, want err")
	}
}

const stubPublicKeyURL = "type.googleapis.com/google.crypto.tink.SomePublicKey"
const stubPrivateKeyURL = "type.googleapis.com/google.crypto.tink.SomePrivateKey"

var stubPrefix = []byte{0x01, 0x01, 0x02, 0x03, 0x04}

type stubFullHybridEncrypt struct{}

func (s *stubFullHybridEncrypt) Encrypt(data []byte, contextInfo []byte) ([]byte, error) {
	return slices.Concat(stubPrefix, data, contextInfo), nil
}

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equal(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool      { return true }

type stubPublicKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
}

var _ key.Key = (*stubPublicKey)(nil)

func (p *stubPublicKey) Equal(_ key.Key) bool          { return true }
func (p *stubPublicKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPublicKey) IDRequirement() (uint32, bool) { return p.idRequirement, p.HasIDRequirement() }
func (p *stubPublicKey) HasIDRequirement() bool        { return p.prefixType != tinkpb.OutputPrefixType_RAW }

type stubPublicKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubPublicKeySerialization)(nil)

func (s *stubPublicKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubPublicKeyURL,
			Value:           []byte("serialized_public_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
		},
		key.(*stubPublicKey).prefixType,
		key.(*stubPublicKey).idRequirement,
	)
}

type stubPublicKeyParser struct{}

var _ protoserialization.KeyParser = (*stubPublicKeyParser)(nil)

func (s *stubPublicKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubPublicKey{serialization.OutputPrefixType(), idRequirement}, nil
}

type stubFullHybridDecrypt struct{}

func (s *stubFullHybridDecrypt) Decrypt(ct []byte, contextInfo []byte) ([]byte, error) {
	if !bytes.HasPrefix(ct, stubPrefix) {
		return nil, fmt.Errorf("invalid prefix")
	}
	if !bytes.HasSuffix(ct, contextInfo) {
		return nil, fmt.Errorf("invalid contextInfo")
	}
	return bytes.TrimSuffix(bytes.TrimPrefix(ct, stubPrefix), contextInfo), nil
}

type stubPrivateKey struct {
	publicKey *stubPublicKey
}

var _ key.Key = (*stubPrivateKey)(nil)

func (p *stubPrivateKey) Equal(_ key.Key) bool          { return true }
func (p *stubPrivateKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubPrivateKey) IDRequirement() (uint32, bool) { return p.publicKey.IDRequirement() }
func (p *stubPrivateKey) HasIDRequirement() bool        { return p.publicKey.HasIDRequirement() }
func (p *stubPrivateKey) PublicKey() (key.Key, error)   { return p.publicKey, nil }

type stubPrivateKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubPrivateKeySerialization)(nil)

func (s *stubPrivateKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubPrivateKeyURL,
			Value:           []byte("serialized_private_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
		key.(*stubPrivateKey).publicKey.prefixType,
		key.(*stubPrivateKey).publicKey.idRequirement,
	)
}

type stubPrivateKeyParser struct{}

var _ protoserialization.KeyParser = (*stubPrivateKeyParser)(nil)

func (s *stubPrivateKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubPrivateKey{
		publicKey: &stubPublicKey{serialization.OutputPrefixType(), idRequirement},
	}, nil
}

func TestPrimitivesFactoryUsesFullPrimitiveIfRegistered(t *testing.T) {
	defer registryconfig.UnregisterPrimitiveConstructor[*stubPublicKey]()
	defer registryconfig.UnregisterPrimitiveConstructor[*stubPrivateKey]()
	defer protoserialization.UnregisterKeyParser(stubPublicKeyURL)
	defer protoserialization.UnregisterKeyParser(stubPrivateKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubPublicKey]()
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()

	if err := protoserialization.RegisterKeyParser(stubPublicKeyURL, &stubPublicKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(stubPrivateKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPublicKey](&stubPublicKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	// Register a primitive constructor to make sure that the factory uses the
	// full primitive.
	primitiveConstructor := func(key key.Key) (any, error) { return &stubFullHybridEncrypt{}, nil }
	if err := registryconfig.RegisterPrimitiveConstructor[*stubPublicKey](primitiveConstructor); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	decryptPrimitiveConstructor := func(key key.Key) (any, error) { return &stubFullHybridDecrypt{}, nil }
	if err := registryconfig.RegisterPrimitiveConstructor[*stubPrivateKey](decryptPrimitiveConstructor); err != nil {
		t.Fatalf("registryconfig.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubPrivateKey{
		publicKey: &stubPublicKey{
			tinkpb.OutputPrefixType_TINK,
			0x01020304,
		},
	})
	if err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}

	encrypter, err := hybrid.NewHybridEncrypt(publicHandle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
	}
	data := []byte("data")
	contextInfo := []byte("contextInfo")
	ciphertext, err := encrypter.Encrypt(data, contextInfo)
	if err != nil {
		t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(ciphertext, slices.Concat(stubPrefix, data, contextInfo)) {
		t.Errorf("ciphertext = %q, want: %q", ciphertext, data)
	}

	decrypter, err := hybrid.NewHybridDecrypt(handle)
	if err != nil {
		t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
	}

	plaintext, err := decrypter.Decrypt(ciphertext, contextInfo)
	if err != nil {
		t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("plaintext = %q, want: %q", plaintext, data)
	}
}

type stubLegacyHybridEncrypt struct{}

func (s *stubLegacyHybridEncrypt) Encrypt(data, contextInfo []byte) ([]byte, error) {
	return slices.Concat([]byte("legacy_primitive"), data, contextInfo), nil
}

type stubLegacyHybridDecrypt struct{}

func (s *stubLegacyHybridDecrypt) Decrypt(ct, contextInfo []byte) ([]byte, error) {
	return bytes.TrimSuffix(bytes.TrimPrefix(ct, []byte("legacy_primitive")), contextInfo), nil
}

type stubPublicKeyManager struct{}

var _ registry.KeyManager = (*stubPublicKeyManager)(nil)

func (km *stubPublicKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPublicKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPublicKeyManager) DoesSupport(keyURL string) bool { return keyURL == stubPublicKeyURL }
func (km *stubPublicKeyManager) TypeURL() string                { return stubPublicKeyURL }
func (km *stubPublicKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacyHybridEncrypt{}, nil
}

type stubPrivateKeyManager struct{}

var _ registry.KeyManager = (*stubPrivateKeyManager)(nil)

func (km *stubPrivateKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPrivateKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubPrivateKeyManager) DoesSupport(keyURL string) bool { return keyURL == stubPrivateKeyURL }
func (km *stubPrivateKeyManager) TypeURL() string                { return stubPrivateKeyURL }
func (km *stubPrivateKeyManager) Primitive(_ []byte) (any, error) {
	return &stubLegacyHybridDecrypt{}, nil
}

func TestPrimitiveFactoryUsesLegacyPrimitive(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubPublicKeyURL)
	defer protoserialization.UnregisterKeyParser(stubPrivateKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubPublicKey]()
	defer protoserialization.UnregisterKeySerializer[*stubPrivateKey]()

	if err := protoserialization.RegisterKeyParser(stubPublicKeyURL, &stubPublicKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeyParser(stubPrivateKeyURL, &stubPrivateKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPublicKey](&stubPublicKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubPrivateKey](&stubPrivateKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	if err := registry.RegisterKeyManager(&stubPublicKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	if err := registry.RegisterKeyManager(&stubPrivateKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	data := []byte("data")
	contextInfo := []byte("contextInfo")
	legacyPrefix := []byte("legacy_primitive")
	for _, tc := range []struct {
		name           string
		key            *stubPrivateKey
		wantCiphertext []byte
	}{
		{
			name: "TINK",
			key: &stubPrivateKey{
				publicKey: &stubPublicKey{
					prefixType:    tinkpb.OutputPrefixType_TINK,
					idRequirement: 0x01020304,
				},
			},
			wantCiphertext: slices.Concat([]byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}, legacyPrefix, data, contextInfo),
		},
		{
			name: "LEGACY",
			key: &stubPrivateKey{
				publicKey: &stubPublicKey{
					prefixType:    tinkpb.OutputPrefixType_LEGACY,
					idRequirement: 0x01020304,
				},
			},
			wantCiphertext: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04}, legacyPrefix, data, contextInfo),
		},
		{
			name: "CRUNCHY",
			key: &stubPrivateKey{
				publicKey: &stubPublicKey{
					prefixType:    tinkpb.OutputPrefixType_CRUNCHY,
					idRequirement: 0x01020304,
				},
			},
			wantCiphertext: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04}, legacyPrefix, data, contextInfo),
		},
		{
			name: "RAW",
			key: &stubPrivateKey{
				publicKey: &stubPublicKey{
					prefixType:    tinkpb.OutputPrefixType_RAW,
					idRequirement: 0,
				},
			},
			wantCiphertext: slices.Concat(legacyPrefix, data, contextInfo),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			km := keyset.NewManager()
			keyID, err := km.AddKey(tc.key)
			if err != nil {
				t.Fatalf("km.AddKey() err = %v, want nil", err)
			}
			if err := km.SetPrimary(keyID); err != nil {
				t.Fatalf("km.SetPrimary() err = %v, want nil", err)
			}
			handle, err := km.Handle()
			if err != nil {
				t.Fatalf("km.Handle() err = %v, want nil", err)
			}

			publicHandle, err := handle.Public()
			if err != nil {
				t.Fatalf("handle.Public() err = %v, want nil", err)
			}

			encrypter, err := hybrid.NewHybridEncrypt(publicHandle)
			if err != nil {
				t.Fatalf("hybrid.NewHybridEncrypt() err = %v, want nil", err)
			}
			ciphertext, err := encrypter.Encrypt(data, contextInfo)
			if err != nil {
				t.Fatalf("encrypter.Encrypt() err = %v, want nil", err)
			}
			if got, want := ciphertext, tc.wantCiphertext; !bytes.Equal(want, got) {
				t.Errorf("ciphertext = %q, want: %q", got, want)
			}

			decrypter, err := hybrid.NewHybridDecrypt(handle)
			if err != nil {
				t.Fatalf("hybrid.NewHybridDecrypt() err = %v, want nil", err)
			}

			plaintext, err := decrypter.Decrypt(ciphertext, contextInfo)
			if err != nil {
				t.Fatalf("decrypter.Decrypt() err = %v, want nil", err)
			}
			if got, want := plaintext, data; !bytes.Equal(got, want) {
				t.Errorf("plaintext = %q, want: %q", got, want)
			}
		})
	}
}
