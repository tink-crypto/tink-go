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

package daead_test

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/testing/stubkeymanager"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	// encrypt with non-raw key.
	keyset := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a non-raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %s, want nil", err)
	}
	d, err := daead.New(keysetHandle)
	if err != nil {
		t.Errorf("daead.New failed: %s", err)
	}
	expectedPrefix, err := cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Fatalf("cryptofmt.OutputPrefix() err = %s, want nil", err)
	}
	if err := validateDAEADFactoryCipher(d, d, expectedPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a non-primary RAW key in keyset and decrypt with the keyset.
	{
		rawKey := keyset.Key[1]
		if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
			t.Errorf("expect a raw key")
		}
		keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
		keysetHandle2, err := testkeyset.NewHandle(keyset2)
		if err != nil {
			t.Fatalf("testkeyset.NewHandle() err = %s, want nil", err)
		}
		d2, err := daead.New(keysetHandle2)
		if err != nil {
			t.Errorf("daead.New failed: %s", err)
		}
		if err := validateDAEADFactoryCipher(d2, d, cryptofmt.RawPrefix); err != nil {
			t.Errorf("invalid cipher: %s", err)
		}
	}

	// encrypt with a random key from a new keyset, decrypt with the original keyset should fail.
	{
		keyset2 := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_TINK)
		newPK := keyset2.Key[0]
		if newPK.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
			t.Errorf("expect a non-raw key")
		}
		keysetHandle2, err := testkeyset.NewHandle(keyset2)
		if err != nil {
			t.Fatalf("testkeyset.NewHandle() err = %s, want nil", err)
		}
		d2, err := daead.New(keysetHandle2)
		if err != nil {
			t.Errorf("daead.New failed: %s", err)
		}
		expectedPrefix, err = cryptofmt.OutputPrefix(newPK)
		if err != nil {
			t.Fatalf("cryptofmt.OutputPrefix() err = %s, want nil", err)
		}
		err = validateDAEADFactoryCipher(d2, d, expectedPrefix)
		if err == nil || !strings.Contains(err.Error(), "decryption failed") {
			t.Errorf("expect decryption to fail with random key: %s", err)
		}
	}
}

func TestFactoryRawKeyAsPrimary(t *testing.T) {
	keyset := testutil.NewTestAESSIVKeyset(tinkpb.OutputPrefixType_RAW)
	if keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("primary key is not a raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Errorf("testkeyset.NewHandle() err = %s, want nil", err)
	}
	d, err := daead.New(keysetHandle)
	if err != nil {
		t.Errorf("cannot get primitive from keyset handle: %s", err)
	}
	if err := validateDAEADFactoryCipher(d, d, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}
}

func validateDAEADFactoryCipher(encryptCipher, decryptCipher tink.DeterministicAEAD, expectedPrefix string) error {
	prefixSize := len(expectedPrefix)
	// regular plaintext.
	pt := random.GetRandomBytes(20)
	aad := random.GetRandomBytes(20)
	ct, err := encryptCipher.EncryptDeterministically(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed with regular plaintext: %s", err)
	}
	decrypted, err := decryptCipher.DecryptDeterministically(ct, aad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with regular plaintext: err: %s, pt: %s, decrypted: %s", err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with regular plaintext")
	}

	// short plaintext.
	pt = random.GetRandomBytes(1)
	ct, err = encryptCipher.EncryptDeterministically(pt, aad)
	if err != nil {
		return fmt.Errorf("encryption failed with short plaintext: %s", err)
	}
	decrypted, err = decryptCipher.DecryptDeterministically(ct, aad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with short plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with short plaintext")
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = daead.New(wrongKH)
	if err == nil {
		t.Fatal("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = daead.New(goodKH)
	if err != nil {
		t.Fatalf("calling New() with good *keyset.Handle failed: %s", err)
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsEncryptionDecryptionWithPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
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
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	pt := []byte("HELLO_WORLD")
	ct, err := p.EncryptDeterministically(pt, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				Status:    monitoring.Enabled,
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				KeyType:   "tink.AesSivKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(pt),
			Context:  monitoring.NewContext("daead", "encrypt", wantKeysetInfo),
		},
		{
			KeyID:    mh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
			Context:  monitoring.NewContext("daead", "decrypt", wantKeysetInfo),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsEncryptionDecryptionWithoutPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	template := daead.AESSIVKeyTemplate()
	// There's currently not a raw template in the public API, but
	// we add a test by customizing the output prefix of an existing one.
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
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
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("hello_world")
	aad := []byte("_!")
	ct, err := p.EncryptDeterministically(data, aad)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, aad); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				Status:    monitoring.Enabled,
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				KeyType:   "tink.AesSivKey",
				KeyPrefix: "RAW",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("daead", "encrypt", wantKeysetInfo),
			KeyID:    wantKeysetInfo.PrimaryKeyID,
			NumBytes: len(data),
		},
		{
			Context:  monitoring.NewContext("daead", "decrypt", wantKeysetInfo),
			KeyID:    wantKeysetInfo.PrimaryKeyID,
			NumBytes: len(ct),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

func TestFactoryWithMonitoringPrimitiveWithMultipleKeysLogsEncryptionDecryption(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	numKeys := 4
	keyIDs := make([]uint32, numKeys, numKeys)
	var err error
	for i := 0; i < numKeys; i++ {
		keyIDs[i], err = manager.Add(daead.AESSIVKeyTemplate())
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
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("YELLOW_ORANGE")
	ct, err := p.EncryptDeterministically(data, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(annotations, kh.KeysetInfo().GetPrimaryKeyId(), []*monitoring.Entry{
		{
			KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
		{
			KeyID:     keyIDs[2],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
		{
			KeyID:     keyIDs[3],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesSivKey",
			KeyPrefix: "TINK",
		},
	})
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				wantKeysetInfo,
			),
		},
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
			Context: monitoring.NewContext(
				"daead",
				"decrypt",
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

func TestPrimitiveFactoryWithMonitoringAnnotationsEncryptionFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	typeURL := "TestFactoryWithMonitoringPrimitiveEncryptionFailureIsLogged"
	km := &stubkeymanager.StubKeyManager{
		URL:  typeURL,
		Prim: &testutil.AlwaysFailingDeterministicAead{Error: fmt.Errorf("failed")},
		KeyData: &tinkpb.KeyData{
			TypeUrl:         typeURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
	}
	if err := registry.RegisterKeyManager(km); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	template := &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
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
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	if _, err := p.EncryptDeterministically(nil, nil); err == nil {
		t.Fatalf("EncryptDeterministically() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
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

func TestPrimitiveFactoryWithMonitoringAnnotationsDecryptionFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
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
	p, err := daead.New(mh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically([]byte("invalid_data"), nil); err == nil {
		t.Fatalf("DecryptDeterministically() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"daead",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
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

func TestFactoryWithMonitoringMultiplePrimitivesLogOperations(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh1, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	// Annotations are only supported throught the `insecurecleartextkeyset` API.
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh1, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh1, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p1, err := daead.New(mh1)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	kh2, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff.Reset()
	if err := insecurecleartextkeyset.Write(kh2, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	mh2, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	p2, err := daead.New(mh2)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	d1 := []byte("YELLOW_ORANGE")
	if _, err := p1.EncryptDeterministically(d1, nil); err != nil {
		t.Fatalf("p1.EncryptDeterministically() err = %v, want nil", err)
	}
	d2 := []byte("ORANGE_BLUE")
	if _, err := p2.EncryptDeterministically(d2, nil); err != nil {
		t.Fatalf("p2.EncryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh1.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(d1),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh1.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh1.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
		{
			KeyID:    kh2.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(d2),
			Context: monitoring.NewContext(
				"daead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh2.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh2.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesSivKey",
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

func TestPrimitiveFactoryEncryptDecryptWithoutAnnotationsDoesNotMonitor(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p, err := daead.New(kh)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("hello_world")
	ct, err := p.EncryptDeterministically(data, nil)
	if err != nil {
		t.Fatalf("p.EncryptDeterministically() err = %v, want nil", err)
	}
	if _, err := p.DecryptDeterministically(ct, nil); err != nil {
		t.Fatalf("p.DecryptDeterministically() err = %v, want nil", err)
	}
	got := client.Events()
	if len(got) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(got))
	}
}

const (
	stubKeyURL        = "type.googleapis.com/google.crypto.tink.SomeKey"
	fullDAEADPrefix   = "full_dead_prefix"
	legacyDAEADPrefix = "legacy_dead_prefix"
)

type stubFullDEAD struct{}

var _ tink.DeterministicAEAD = (*stubFullDEAD)(nil)

func (s *stubFullDEAD) EncryptDeterministically(pt, ad []byte) ([]byte, error) {
	return slices.Concat([]byte(fullDAEADPrefix), pt), nil
}

func (s *stubFullDEAD) DecryptDeterministically(ct, ad []byte) ([]byte, error) {
	return ct[len(fullDAEADPrefix):], nil
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
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
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

func mustCreateKeyset(t *testing.T, key key.Key) *keyset.Handle {
	t.Helper()
	km := keyset.NewManager()
	keyID, err := km.AddKey(key)
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
	return handle
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
	primitiveConstructor := func(key key.Key) (any, error) { return &stubFullDEAD{}, nil }
	if err := primitiveregistry.RegisterPrimitiveConstructor[*stubKey](primitiveConstructor); err != nil {
		t.Fatalf("primitiveregistry.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}

	handle := mustCreateKeyset(t, &stubKey{
		tinkpb.OutputPrefixType_TINK,
		0x1234,
	})
	encrypter, err := daead.New(handle)
	if err != nil {
		t.Fatalf("daead.New() err = %v, want nil", err)
	}
	data := []byte("data")
	ad := []byte("ad")
	ciphertext, err := encrypter.EncryptDeterministically(data, ad)
	if err != nil {
		t.Fatalf("encrypter.Sign() err = %v, want nil", err)
	}
	if !bytes.Equal(ciphertext, slices.Concat([]byte(fullDAEADPrefix), data)) {
		t.Errorf("ciphertext = %q, want: %q", ciphertext, data)
	}
}

type stubLegacyDEAD struct{}

var _ tink.DeterministicAEAD = (*stubLegacyDEAD)(nil)

func (s *stubLegacyDEAD) EncryptDeterministically(pt, ad []byte) ([]byte, error) {
	return slices.Concat([]byte(legacyDAEADPrefix), pt), nil
}

func (s *stubLegacyDEAD) DecryptDeterministically(ct, ad []byte) ([]byte, error) {
	return ct[len(legacyDAEADPrefix):], nil
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
func (km *stubKeyManager) Primitive(_ []byte) (any, error) { return &stubLegacyDEAD{}, nil }

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
	legacyPrefix := []byte(legacyDAEADPrefix)
	for _, tc := range []struct {
		name           string
		handle         *keyset.Handle
		wantCiphertext []byte
	}{
		{
			name:           "TINK",
			handle:         mustCreateKeyset(t, &stubKey{tinkpb.OutputPrefixType_TINK, 0x1234}),
			wantCiphertext: slices.Concat([]byte{cryptofmt.TinkStartByte, 0x00, 0x00, 0x12, 0x34}, legacyPrefix, data),
		},
		{
			name:           "CRUNCHY",
			handle:         mustCreateKeyset(t, &stubKey{tinkpb.OutputPrefixType_CRUNCHY, 0x1234}),
			wantCiphertext: slices.Concat([]byte{cryptofmt.LegacyStartByte, 0x00, 0x00, 0x12, 0x34}, legacyPrefix, data),
		},
		{
			name:           "RAW",
			handle:         mustCreateKeyset(t, &stubKey{tinkpb.OutputPrefixType_RAW, 0}),
			wantCiphertext: slices.Concat(legacyPrefix, data),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a keyset with a single key.
			encrypter, err := daead.New(tc.handle)
			if err != nil {
				t.Fatalf("daead.New() err = %v, want nil", err)
			}
			ad := []byte("ad")
			ciphertext, err := encrypter.EncryptDeterministically(data, ad)
			if err != nil {
				t.Fatalf("encrypter.Sign() err = %v, want nil", err)
			}
			if got, want := ciphertext, tc.wantCiphertext; !bytes.Equal(got, want) {
				t.Errorf("ciphertext = %q, want: %q", got, want)
			}
		})
	}
}

func TestNewWithConfig(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(stubKeyURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()

	if err := protoserialization.RegisterKeyParser(stubKeyURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	builderWithFullPrimitive := config.NewBuilder()
	if err := builderWithFullPrimitive.RegisterPrimitiveConstructor(reflect.TypeFor[*stubKey](), func(key key.Key) (any, error) { return &stubFullDEAD{}, nil }, internalapi.Token{}); err != nil {
		t.Fatalf("builderWithFullPrimitive.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithFullPrimitive := builderWithFullPrimitive.Build()

	builderWithLegacyPrimitive := config.NewBuilder()
	if err := builderWithLegacyPrimitive.RegisterKeyManager(stubKeyURL, &stubKeyManager{}, internalapi.Token{}); err != nil {
		t.Fatalf("builderWithLegacyPrimitive.RegisterKeyManager() err = %v, want nil", err)
	}
	configWithLegacyPrimitive := builderWithLegacyPrimitive.Build()

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

	for _, tc := range []struct {
		name       string
		kh         *keyset.Handle
		config     keyset.Config
		wantPrefix []byte
	}{
		{
			name:       "full primitive",
			config:     &configWithFullPrimitive,
			kh:         handle,
			wantPrefix: slices.Concat([]byte(fullDAEADPrefix)),
		},
		{
			name:       "legacy primitive",
			config:     &configWithLegacyPrimitive,
			kh:         handle,
			wantPrefix: slices.Concat([]byte{cryptofmt.TinkStartByte, 0x01, 0x02, 0x03, 0x04}, []byte(legacyDAEADPrefix)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer internalregistry.ClearMonitoringClient()
			client := fakemonitoring.NewClient("fake-client")
			if err := internalregistry.RegisterMonitoringClient(client); err != nil {
				t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
			}
			encrypter, err := daead.NewWithConfig(tc.kh, tc.config)
			if err != nil {
				t.Fatalf("daead.NewWithConfig(tc.kh, config) err = %v, want nil", err)
			}

			m, err := encrypter.EncryptDeterministically([]byte("message"), nil)
			if err != nil {
				t.Fatalf("encrypter.EncryptDeterministically() err = %v, want nil", err)
			}
			if !bytes.HasPrefix(m, tc.wantPrefix) {
				t.Errorf("m = %q, want prefix: %q", m, tc.wantPrefix)
			}
		})
	}
}
