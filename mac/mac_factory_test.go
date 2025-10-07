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

package mac_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubkeymanager"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/internal/mactest"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"

	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_TINK {
		t.Errorf("expect a tink key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	expectedPrefix, err := cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Errorf("cryptofmt.OutputPrefix failed: %s", err)
	}

	if err := verifyMacPrimitive(p, p, expectedPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}

	// mac with a primary RAW key, verify with the keyset
	rawKey := keyset.Key[1]
	if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	keysetHandle2, err := testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p2, err := mac.New(keysetHandle2)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	if err := verifyMacPrimitive(p2, p, cryptofmt.RawPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}

	// mac with a random key not in the keyset, verify with the keyset should fail
	keyset2 = testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_TINK)
	primaryKey = keyset2.Key[0]
	expectedPrefix, err = cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Errorf("cryptofmt.OutputPrefix() err = %q, want nil", err)
	}
	keysetHandle2, err = testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}

	p2, err = mac.New(keysetHandle2)
	if err != nil {
		t.Errorf("mac.New: cannot get primitive from keyset handle")
	}
	err = verifyMacPrimitive(p2, p, expectedPrefix, tagSize)
	if err == nil || !strings.Contains(err.Error(), "mac verification failed") {
		t.Errorf("Invalid MAC, shouldn't return valid")
	}
}

func TestFactoryRawKey(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_RAW)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	if err := verifyMacPrimitive(p, p, cryptofmt.RawPrefix, tagSize); err != nil {
		t.Errorf("invalid primitive: %s", err)
	}
}

func TestFactoryLegacyKey(t *testing.T) {
	tagSize := uint32(16)
	keyset := testutil.NewTestHMACKeyset(tagSize, tinkpb.OutputPrefixType_LEGACY)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY {
		t.Errorf("expect a legacy key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	data := []byte("some data")
	tag, err := p.ComputeMAC(data)
	if err != nil {
		t.Errorf("mac computation failed: %s", err)
	}
	if err = p.VerifyMAC(tag, data); err != nil {
		t.Errorf("mac verification failed: %s", err)
	}
}

func TestFactoryLegacyFixedKeyFixedTag(t *testing.T) {
	tagSize := uint32(16)
	params := testutil.NewHMACParams(commonpb.HashType_SHA256, tagSize)
	keyValue := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	key := &hmacpb.HmacKey{
		Version:  0,
		Params:   params,
		KeyValue: keyValue,
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		t.Errorf("failed serializing proto: %v", err)
	}
	keyData := &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.HmacKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}
	keyset := testutil.NewTestKeyset(keyData, tinkpb.OutputPrefixType_LEGACY)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType != tinkpb.OutputPrefixType_LEGACY {
		t.Errorf("expect a legacy key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle failed: %s", err)
	}
	p, err := mac.New(keysetHandle)
	if err != nil {
		t.Errorf("mac.New failed: %s", err)
	}
	data := []byte("hello")
	tag := []byte{0, 0, 0, 0, 42, 64, 150, 12, 207, 250, 175, 32, 216, 164, 77, 69, 28, 29, 204, 235, 75}
	if err = p.VerifyMAC(tag, data); err != nil {
		t.Errorf("compatibleTag verification failed: %s", err)
	}
}

func verifyMacPrimitive(computePrimitive, verifyPrimitive tink.MAC, expectedPrefix string, tagSize uint32) error {
	data := []byte("hello")
	tag, err := computePrimitive.ComputeMAC(data)
	if err != nil {
		return fmt.Errorf("mac computation failed: %s", err)
	}
	prefixSize := len(expectedPrefix)
	if string(tag[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix")
	}
	if prefixSize+int(tagSize) != len(tag) {
		return fmt.Errorf("incorrect tag length")
	}
	if err = verifyPrimitive.VerifyMAC(tag, data); err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}

	// Modify plaintext or tag and make sure VerifyMAC failed.
	var dataAndTag []byte
	dataAndTag = append(dataAndTag, data...)
	dataAndTag = append(dataAndTag, tag...)
	if err = verifyPrimitive.VerifyMAC(dataAndTag[len(data):], dataAndTag[:len(data)]); err != nil {
		return fmt.Errorf("mac verification failed: %s", err)
	}
	for i := 0; i < len(dataAndTag); i++ {
		tmp := dataAndTag[i]
		for j := 0; j < 8; j++ {
			dataAndTag[i] ^= 1 << uint8(j)
			if err = verifyPrimitive.VerifyMAC(dataAndTag[len(data):], dataAndTag[:len(data)]); err == nil {
				return fmt.Errorf("invalid tag or plaintext, mac should be invalid")
			}
			dataAndTag[i] = tmp
		}
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = mac.New(wrongKH)
	if err == nil {
		t.Fatal("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = mac.New(goodKH)
	if err != nil {
		t.Fatalf("calling New() with good *keyset.Handle failed: %s", err)
	}
}

func TestPrimitiveFactoryMonitoringWithoutAnnotationsDoesNotLog(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate()) err = %v, want nil", err)
	}
	p, err := mac.New(kh)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	data := []byte("data")
	tag, err := p.ComputeMAC(data)
	if err != nil {
		t.Fatalf("p.ComputeMAC() err = %v, want nil", err)
	}
	if err := p.VerifyMAC(tag, data); err != nil {
		t.Fatalf("p.Verify() err = %v, want nil", err)
	}
	got := client.Events()
	if len(got) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(got))
	}
}

func TestFactoryWithMonitoringPrimitiveWithMultipleKeysLogsComputeVerify(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	keyIDs := make([]uint32, 4, 4)
	var err error
	for i, tm := range []*tinkpb.KeyTemplate{
		mac.HMACSHA256Tag256KeyTemplate(),
		mac.HMACSHA256Tag128KeyTemplate(),
		mac.HMACSHA512Tag512KeyTemplate(),
		mac.AESCMACTag128KeyTemplate(),
	} {
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
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := mac.New(mh)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	data := random.GetRandomBytes(50)
	tag, err := p.ComputeMAC(data)
	if err != nil {
		t.Fatalf("p.ComputeMAC() err = %v, want nil", err)
	}
	if err := p.VerifyMAC(tag, data); err != nil {
		t.Fatalf("p.VerifyMAC() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	wantKeysetInfo := &monitoring.KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: kh.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[2],
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacKey",
				KeyPrefix: "TINK",
			},
			{
				KeyID:     keyIDs[3],
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesCmacKey",
				KeyPrefix: "TINK",
			},
		},
	}
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context: monitoring.NewContext(
				"mac",
				"compute",
				wantKeysetInfo,
			),
		},
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context: monitoring.NewContext(
				"mac",
				"verify",
				wantKeysetInfo,
			),
		},
	}
	// sort by keyID to avoid non deterministic order.
	entryLessFunc := func(a, b *monitoring.Entry) bool {
		return a.KeyID < b.KeyID
	}
	if !cmp.Equal(got, want, cmpopts.SortSlices(entryLessFunc)) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsComputeFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	// Since this key type will be registered in the registry,
	// we create a very unique typeURL to avoid colliding with other tests.
	typeURL := "TestPrimitiveFactoryWithMonitoringComputeFailureIsLogged"
	template := &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
	}
	km := &stubkeymanager.StubKeyManager{
		URL:  typeURL,
		Prim: &mactest.AlwaysFailingMAC{Error: fmt.Errorf("system failure")},
		Key:  &hmacpb.HmacKey{},
		KeyData: &tinkpb.KeyData{
			TypeUrl: template.TypeUrl,
			Value:   []byte("some_data"),
		},
	}
	if err := registry.RegisterKeyManager(km); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	m, err := mac.New(mh)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	if _, err := m.ComputeMAC([]byte("some_data")); err == nil {
		t.Fatalf("m.ComputeMAC() err = nil, want non-nil error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"mac",
				"compute",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   typeURL,
							KeyPrefix: "LEGACY",
						},
					},
				),
			),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsVerifyFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	m, err := mac.New(mh)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	if err := m.VerifyMAC(nil, nil); err == nil {
		t.Fatalf("m.VerifyMAC() err = nil, want non-nil error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"mac",
				"verify",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.HmacKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsMultiplePrimitivesLogOperations(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	templates := []*tinkpb.KeyTemplate{
		mac.HMACSHA256Tag256KeyTemplate(),
		mac.AESCMACTag128KeyTemplate()}
	handles := make([]*keyset.Handle, len(templates))
	var err error
	annotations := map[string]string{"foo": "bar"}
	for i, tm := range templates {
		handles[i], err = keyset.NewHandle(tm)
		if err != nil {
			t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
		}
		// Annotations are only supported throught the `insecurecleartextkeyset` API.
		buff := &bytes.Buffer{}
		if err := insecurecleartextkeyset.Write(handles[i], keyset.NewBinaryWriter(buff)); err != nil {
			t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
		}
		mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
		if err != nil {
			t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
		}
		p, err := mac.New(mh)
		if err != nil {
			t.Fatalf("mac.New() err = %v, want nil", err)
		}
		if _, err := p.ComputeMAC([]byte(tm.GetTypeUrl())); err != nil {
			t.Fatalf("p.ComputeMAC() err = %v, want nil", err)
		}
	}
	got := client.Events()
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    handles[0].KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(templates[0].GetTypeUrl()),
			Context: monitoring.NewContext(
				"mac",
				"compute",
				monitoring.NewKeysetInfo(
					annotations,
					handles[0].KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     handles[0].KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.HmacKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
		{
			KeyID:    handles[1].KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(templates[1].GetTypeUrl()),
			Context: monitoring.NewContext(
				"mac",
				"compute",
				monitoring.NewKeysetInfo(
					annotations,
					handles[1].KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     handles[1].KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesCmacKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsComputeVerifyLogs(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p, err := mac.New(mh)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	data := []byte("data")
	tag, err := p.ComputeMAC(data)
	if err != nil {
		t.Fatalf("p.ComputeMAC() err = %v, want nil", err)
	}
	if err := p.VerifyMAC(tag, data); err != nil {
		t.Fatalf("p.Verify() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		&fakemonitoring.LogEvent{
			Context:  monitoring.NewContext("mac", "compute", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
		&fakemonitoring.LogEvent{
			Context:  monitoring.NewContext("mac", "verify", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

const stubKeyURL = "type.googleapis.com/google.crypto.tink.SomeKey"

var tinkPrefix = []byte{0x01, 0x01, 0x02, 0x03, 0x04}

type stubFullMAC struct{}

var _ (tink.MAC) = (*stubFullMAC)(nil)

func (s *stubFullMAC) ComputeMAC(data []byte) ([]byte, error) {
	return slices.Concat(tinkPrefix, []byte("_full_mac_"), data), nil
}

func (s *stubFullMAC) VerifyMAC(mac, data []byte) error {
	if !bytes.Equal(mac, slices.Concat(tinkPrefix, []byte("_full_mac_"), data)) {
		return fmt.Errorf("invalid mac")
	}
	return nil
}

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equal(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool      { return true }

type stubKey struct {
	prefixType    tinkpb.OutputPrefixType
	idRequirement uint32
}

var _ key.Key = (*stubKey)(nil)

func (p *stubKey) Equal(_ key.Key) bool          { return true }
func (p *stubKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubKey) IDRequirement() (uint32, bool) { return p.idRequirement, p.HasIDRequirement() }
func (p *stubKey) HasIDRequirement() bool        { return p.prefixType != tinkpb.OutputPrefixType_RAW }
func (p *stubKey) OutputPrefix() []byte {
	prefix, err := cryptofmt.OutputPrefix(&tinkpb.Keyset_Key{OutputPrefixType: p.prefixType, KeyId: p.idRequirement})
	if err != nil {
		panic(err)
	}
	return []byte(prefix)
}

type stubKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubKeySerialization)(nil)

func (s *stubKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         stubKeyURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
		},
		key.(*stubKey).prefixType,
		key.(*stubKey).idRequirement,
	)
}

type stubKeyParser struct{}

var _ protoserialization.KeyParser = (*stubKeyParser)(nil)

func (s *stubKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	idRequirement, _ := serialization.IDRequirement()
	return &stubKey{serialization.OutputPrefixType(), idRequirement}, nil
}

func TestPrimitiveFactoryUsesFullPrimitiveIfRegistered(t *testing.T) {
	defer primitiveregistry.UnregisterPrimitiveConstructor[*stubKey]()
	defer protoserialization.UnregisterKeyParser(stubKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()

	if err := protoserialization.RegisterKeyParser(stubKeyURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}
	// Register a primitive constructor to make sure that the factory uses the
	// full primitive.
	primitiveConstructor := func(key key.Key) (any, error) { return &stubFullMAC{}, nil }
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubKey](primitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	km := keyset.NewManager()
	keyID, err := km.AddKey(&stubKey{
		prefixType:    tinkpb.OutputPrefixType_TINK,
		idRequirement: 0x01020304,
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

	macer, err := mac.New(handle)
	if err != nil {
		t.Fatalf("mac.New() err = %v, want nil", err)
	}
	data := []byte("data")
	m, err := macer.ComputeMAC(data)
	if err != nil {
		t.Fatalf("macer.ComputeMAC() err = %v, want nil", err)
	}
	if !bytes.Equal(m, slices.Concat(tinkPrefix, []byte("_full_mac_"), data)) {
		t.Errorf("m = %q, want: %q", m, data)
	}
	if err := macer.VerifyMAC(m, data); err != nil {
		t.Errorf("macer.VerifyMAC() err = %v, want nil", err)
	}
}

type stubLegacyMAC struct{}

func (s *stubLegacyMAC) ComputeMAC(data []byte) ([]byte, error) {
	return slices.Concat([]byte("_legacy_mac_"), data), nil
}

func (s *stubLegacyMAC) VerifyMAC(mac, data []byte) error {
	if !bytes.Equal(mac, slices.Concat([]byte("_legacy_mac_"), data)) {
		return fmt.Errorf("invalid mac")
	}
	return nil
}

type stubKeyManager struct{}

var _ registry.KeyManager = (*stubKeyManager)(nil)

func (km *stubKeyManager) NewKey(_ []byte) (proto.Message, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) NewKeyData(_ []byte) (*tinkpb.KeyData, error) {
	return nil, fmt.Errorf("not implemented")
}
func (km *stubKeyManager) DoesSupport(keyURL string) bool  { return keyURL == stubKeyURL }
func (km *stubKeyManager) TypeURL() string                 { return stubKeyURL }
func (km *stubKeyManager) Primitive(_ []byte) (any, error) { return &stubLegacyMAC{}, nil }

func TestPrimitiveFactoryUsesLegacyPrimitive(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()

	if err := protoserialization.RegisterKeyParser(stubKeyURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	if err := registry.RegisterKeyManager(&stubKeyManager{}); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}

	data := []byte("data")
	for _, tc := range []struct {
		name    string
		key     *stubKey
		wantMAC []byte
	}{
		{
			name:    "TINK",
			key:     &stubKey{tinkpb.OutputPrefixType_TINK, 0x01020304},
			wantMAC: slices.Concat([]byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}, []byte("_legacy_mac_"), data),
		},
		{
			name:    "LEGACY",
			key:     &stubKey{tinkpb.OutputPrefixType_LEGACY, 0x01020304},
			wantMAC: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04}, []byte("_legacy_mac_"), data, []byte{0x00}),
		},
		{
			name:    "CRUNCHY",
			key:     &stubKey{tinkpb.OutputPrefixType_CRUNCHY, 0x01020304},
			wantMAC: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x01, 0x02, 0x03, 0x04}, []byte("_legacy_mac_"), data),
		},
		{
			name:    "RAW",
			key:     &stubKey{tinkpb.OutputPrefixType_RAW, 0},
			wantMAC: slices.Concat([]byte("_legacy_mac_"), data),
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
			macer, err := mac.New(handle)
			if err != nil {
				t.Fatalf("mac.New() err = %v, want nil", err)
			}
			m, err := macer.ComputeMAC(data)
			if err != nil {
				t.Fatalf("macer.ComputeMAC() err = %v, want nil", err)
			}
			if got, want := m, tc.wantMAC; !bytes.Equal(want, got) {
				t.Errorf("m = %q, want: %q", got, want)
			}
		})
	}
}
