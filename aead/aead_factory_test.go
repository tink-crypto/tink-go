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

package aead_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
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

	agpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	// encrypt with non-raw key
	keyset := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey := keyset.Key[0]
	if primaryKey.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a non-raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %s, want err", err)
	}
	a, err := aead.New(keysetHandle)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	expectedPrefix, err := cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Errorf("cryptofmt.OutputPrefix() err = %s, want nil", err)
	}
	if err := validateAEADFactoryCipher(a, a, expectedPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a non-primary RAW key and decrypt with the keyset
	rawKey := keyset.Key[1]
	if rawKey.OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("expect a raw key")
	}
	keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	keysetHandle2, err := testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %s, want err", err)
	}
	a2, err := aead.New(keysetHandle2)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	if err := validateAEADFactoryCipher(a2, a, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}

	// encrypt with a random key not in the keyset, decrypt with the keyset should fail
	keyset2 = testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_TINK)
	primaryKey = keyset2.Key[0]
	expectedPrefix, err = cryptofmt.OutputPrefix(primaryKey)
	if err != nil {
		t.Errorf("cryptofmt.OutputPrefix() err = %s, want err", err)
	}
	keysetHandle2, err = testkeyset.NewHandle(keyset2)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %s, want err", err)
	}
	a2, err = aead.New(keysetHandle2)
	if err != nil {
		t.Errorf("aead.New failed: %s", err)
	}
	err = validateAEADFactoryCipher(a2, a, expectedPrefix)
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("expect decryption to fail with random key: %s", err)
	}
}

type stubAEAD struct {
	prefix []byte
}

func (a *stubAEAD) Encrypt(p, _ []byte) ([]byte, error) {
	return slices.Concat(a.prefix, p), nil
}
func (a *stubAEAD) Decrypt(c, _ []byte) ([]byte, error) {
	if !bytes.HasPrefix(c, a.prefix) {
		return nil, errors.New("ciphertext does not start with prefix")
	}
	return c[len(a.prefix):], nil
}

func TestNewWithConfig(t *testing.T) {
	annotations := map[string]string{"foo": "bar"}
	// Last key is primary.
	keysetHandleWithPrimaryWithPrefix := mustCreateHandle(t, annotations, aead.AES256GCMNoPrefixKeyTemplate(), aead.AES256GCMKeyTemplate())
	keysetHandleWithPrimaryWithoutPrefix := mustCreateHandle(t, annotations, aead.AES256GCMKeyTemplate(), aead.AES256GCMNoPrefixKeyTemplate())

	cb := config.NewBuilder()
	if err := cb.RegisterPrimitiveConstructor(reflect.TypeFor[*aesgcm.Key](), func(key key.Key) (any, error) {
		return &stubAEAD{prefix: key.(*aesgcm.Key).OutputPrefix()}, nil
	}, internalapi.Token{}); err != nil {
		t.Fatalf("cb.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	c := cb.Build()

	for _, tc := range []struct {
		name       string
		kh         *keyset.Handle
		wantPrefix bool
	}{
		{
			name:       "full primitive primary with prefix",
			kh:         keysetHandleWithPrimaryWithPrefix,
			wantPrefix: true,
		},
		{
			name: "full primitive primary without prefix",
			kh:   keysetHandleWithPrimaryWithoutPrefix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer internalregistry.ClearMonitoringClient()
			client := fakemonitoring.NewClient("fake-client")
			if err := internalregistry.RegisterMonitoringClient(client); err != nil {
				t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
			}
			a, err := aead.NewWithConfig(tc.kh, &c)
			if err != nil {
				t.Fatalf("aead.NewWithConfig(tc.kh, config) err = %v, want nil", err)
			}

			plaintext := []byte("message")
			associatedData := []byte("aad")
			ct, err := a.Encrypt(plaintext, associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt() err = %v, want nil", err)
			}
			primaryEntry, err := tc.kh.Primary()
			if err != nil {
				t.Fatalf("kh.Primary() err = %v, want nil", err)
			}
			prefix := primaryEntry.Key().(*aesgcm.Key).OutputPrefix()
			if tc.wantPrefix && len(prefix) == 0 {
				t.Fatalf("want prefix, got empty prefix")
			}
			if got, want := ct, slices.Concat(prefix, plaintext); !bytes.Equal(got, want) {
				t.Errorf("aead.Encrypt() = %q, want %q", got, want)
			}

			pt, err := a.Decrypt(ct, associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt() err = %v, want nil", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("aead.Decrypt() = %q, want %q", pt, plaintext)
			}

			// Make sure that the monitoring logs the correct number of bytes.
			gotEvents := client.Events()
			if len(gotEvents) != 2 {
				t.Fatalf("len(client.Events()) = %d, want 1", len(gotEvents))
			}
			wantEvents := []*fakemonitoring.LogEvent{
				{
					KeyID:    primaryEntry.KeyID(),
					NumBytes: len(plaintext),
					Context:  monitoring.NewContext("aead", "encrypt", nil), // KeysetInfo is not relevant for this test.
				},
				{
					KeyID:    primaryEntry.KeyID(),
					NumBytes: len(ct),
					Context:  monitoring.NewContext("aead", "decrypt", nil), // KeysetInfo is not relevant for this test.
				},
			}
			if diff := cmp.Diff(gotEvents, wantEvents, cmpopts.IgnoreFields(fakemonitoring.LogEvent{}, "Context.KeysetInfo")); diff != "" {
				t.Errorf("got != want, diff: %v", diff)
			}
		})
	}
}

func TestFactoryRawKeyAsPrimary(t *testing.T) {
	keyset := testutil.NewTestAESGCMKeyset(tinkpb.OutputPrefixType_RAW)
	if keyset.Key[0].OutputPrefixType != tinkpb.OutputPrefixType_RAW {
		t.Errorf("primary key is not a raw key")
	}
	keysetHandle, err := testkeyset.NewHandle(keyset)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %s, want err", err)
	}

	a, err := aead.New(keysetHandle)
	if err != nil {
		t.Errorf("cannot get primitive from keyset handle: %s", err)
	}
	if err := validateAEADFactoryCipher(a, a, cryptofmt.RawPrefix); err != nil {
		t.Errorf("invalid cipher: %s", err)
	}
}

func validateAEADFactoryCipher(encryptCipher, decryptCipher tink.AEAD, expectedPrefix string) error {
	prefixSize := len(expectedPrefix)
	// regular plaintext
	pt := random.GetRandomBytes(20)
	ad := random.GetRandomBytes(20)
	ct, err := encryptCipher.Encrypt(pt, ad)
	if err != nil {
		return fmt.Errorf("encryption failed with regular plaintext: %s", err)
	}
	decrypted, err := decryptCipher.Decrypt(ct, ad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with regular plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with regular plaintext")
	}
	if prefixSize+len(pt)+subtle.AESGCMIVSize+subtle.AESGCMTagSize != len(ct) {
		return fmt.Errorf("lengths of plaintext and ciphertext don't match with regular plaintext")
	}

	// short plaintext
	pt = random.GetRandomBytes(1)
	ct, err = encryptCipher.Encrypt(pt, ad)
	if err != nil {
		return fmt.Errorf("encryption failed with short plaintext: %s", err)
	}
	decrypted, err = decryptCipher.Decrypt(ct, ad)
	if err != nil || !bytes.Equal(decrypted, pt) {
		return fmt.Errorf("decryption failed with short plaintext: err: %s, pt: %s, decrypted: %s",
			err, pt, decrypted)
	}
	if string(ct[:prefixSize]) != expectedPrefix {
		return fmt.Errorf("incorrect prefix with short plaintext")
	}
	if prefixSize+len(pt)+subtle.AESGCMIVSize+subtle.AESGCMTagSize != len(ct) {
		return fmt.Errorf("lengths of plaintext and ciphertext don't match with short plaintext")
	}
	return nil
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = aead.New(wrongKH)
	if err == nil {
		t.Fatalf("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = aead.New(goodKH)
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
	annotations := map[string]string{"foo": "bar"}
	kh := mustCreateHandle(t, annotations, aead.AES128GCMKeyTemplate())
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	data := []byte("HELLO_WORLD")
	ad := []byte("_!")
	ct, err := p.Encrypt(data, ad)
	if err != nil {
		t.Fatalf("p.Encrypt() err = %v, want nil", err)
	}
	if _, err := p.Decrypt(ct, ad); err != nil {
		t.Fatalf("p.Decrypt() err = %v, want nil", err)
	}
	failures := client.Failures()
	if len(failures) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(failures))
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesGcmKey",
				KeyPrefix: "TINK",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context:  monitoring.NewContext("aead", "encrypt", wantKeysetInfo),
		},
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
			Context:  monitoring.NewContext("aead", "decrypt", wantKeysetInfo),
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("got != want, diff: %v", diff)
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsEncryptionDecryptionWithoutPrefix(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	kh := mustCreateHandle(t, annotations, aead.AES256GCMNoPrefixKeyTemplate())
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	data := []byte("HELLO_WORLD")
	ct, err := p.Encrypt(data, nil)
	if err != nil {
		t.Fatalf("p.Encrypt() err = %v, want nil", err)
	}
	if _, err := p.Decrypt(ct, nil); err != nil {
		t.Fatalf("p.Decrypt() err = %v, want nil", err)
	}
	failures := client.Failures()
	if len(failures) != 0 {
		t.Errorf("len(client.Failures()) = %d, want = 0", len(failures))
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(
		annotations,
		kh.KeysetInfo().GetPrimaryKeyId(),
		[]*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesGcmKey",
				KeyPrefix: "RAW",
			},
		},
	)
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
			Context:  monitoring.NewContext("aead", "encrypt", wantKeysetInfo),
		},
		{
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(ct),
			Context:  monitoring.NewContext("aead", "decrypt", wantKeysetInfo),
		},
	}
	if cmp.Diff(got, want) != "" {
		t.Errorf("%v", cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotatiosMultipleKeysLogsEncryptionDecryption(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("registry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	keyTemplates := []*tinkpb.KeyTemplate{
		aead.AES128GCMKeyTemplate(),
		aead.AES256GCMNoPrefixKeyTemplate(),
		aead.AES128CTRHMACSHA256KeyTemplate(),
		aead.XChaCha20Poly1305KeyTemplate(),
	}
	keyIDs := make([]uint32, len(keyTemplates), len(keyTemplates))
	var err error
	for i, kt := range keyTemplates {
		keyIDs[i], err = manager.Add(kt)
		if err != nil {
			t.Fatalf("manager.Add(%v) err = %v, want nil", kt, err)
		}
	}
	if err := manager.SetPrimary(keyIDs[1]); err != nil {
		t.Fatalf("manager.SetPrimary(%d) err = %v, want nil", keyIDs[1], err)
	}
	if err := manager.Disable(keyIDs[0]); err != nil {
		t.Fatalf("manager.Disable(%d) err = %v, want nil", keyIDs[0], err)
	}
	annotations := map[string]string{"foo": "bar"}
	if err := manager.SetAnnotations(annotations); err != nil {
		t.Fatalf("manager.SetAnnotations(%v) err = %v, want nil", annotations, err)
	}
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	data := []byte("YELLOW_ORANGE")
	ct, err := p.Encrypt(data, nil)
	if err != nil {
		t.Fatalf("p.Encrypt() err = %v, want nil", err)
	}
	if _, err := p.Decrypt(ct, nil); err != nil {
		t.Fatalf("p.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := monitoring.NewKeysetInfo(annotations, keyIDs[1], []*monitoring.Entry{
		{
			KeyID:     keyIDs[1],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesGcmKey",
			KeyPrefix: "RAW",
		},
		{
			KeyID:     keyIDs[2],
			Status:    monitoring.Enabled,
			KeyType:   "tink.AesCtrHmacAeadKey",
			KeyPrefix: "TINK",
		},
		{
			KeyID:     keyIDs[3],
			Status:    monitoring.Enabled,
			KeyType:   "tink.XChaCha20Poly1305Key",
			KeyPrefix: "TINK",
		},
	})
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    keyIDs[1],
			NumBytes: len(data),
			Context: monitoring.NewContext(
				"aead",
				"encrypt",
				wantKeysetInfo,
			),
		},
		{
			KeyID:    keyIDs[1],
			NumBytes: len(ct),
			Context: monitoring.NewContext(
				"aead",
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
	template := &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_LEGACY,
	}
	km := &stubkeymanager.StubKeyManager{
		URL:  typeURL,
		Key:  &agpb.AesGcmKey{},
		Prim: &testutil.AlwaysFailingAead{Error: errors.New("failed")},
		KeyData: &tinkpb.KeyData{
			TypeUrl:         typeURL,
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
			Value:           []byte("serialized_key"),
		},
	}
	if err := registry.RegisterKeyManager(km); err != nil {
		t.Fatalf("registry.RegisterKeyManager() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	kh := mustCreateHandle(t, annotations, template)
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	if _, err := p.Encrypt(nil, nil); err == nil {
		t.Fatalf("Encrypt() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"aead",
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
	if cmp.Diff(got, want) != "" {
		t.Errorf("%v", cmp.Diff(got, want))
	}
}

func TestPrimitiveFactoryWithMonitoringAnnotationsDecryptionFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	kh := mustCreateHandle(t, annotations, aead.AES128GCMKeyTemplate())
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	if _, err := p.Decrypt([]byte("invalid_data"), nil); err == nil {
		t.Fatalf("Decrypt() err = nil, want error")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"aead",
				"decrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesGcmKey",
							KeyPrefix: "TINK",
						},
					},
				),
			),
		},
	}
	if cmp.Diff(got, want) != "" {
		t.Errorf("%v", cmp.Diff(got, want))
	}
}

func mustCreateHandle(t *testing.T, annotations map[string]string, templates ...*tinkpb.KeyTemplate) *keyset.Handle {
	t.Helper()
	km := keyset.NewManager()
	for _, template := range templates {
		keyID, err := km.Add(template)
		if err != nil {
			t.Fatalf("km.Add(%v) err = %v, want nil", template, err)
		}
		if err := km.SetPrimary(keyID); err != nil {
			t.Fatalf("km.SetPrimary(%d) err = %v, want nil", keyID, err)
		}
	}
	if err := km.SetAnnotations(annotations); err != nil {
		t.Fatalf("km.SetAnnotations(%v) err = %v, want nil", annotations, err)
	}
	kh, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return kh
}

func TestFactoryWithMonitoringMultiplePrimitivesLogOperations(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := &fakemonitoring.Client{Name: ""}
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	annotations := map[string]string{"foo": "bar"}
	kh1 := mustCreateHandle(t, annotations, aead.AES128GCMKeyTemplate())
	p1, err := aead.New(kh1)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	kh2 := mustCreateHandle(t, annotations, aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p2, err := aead.New(kh2)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	d1 := []byte("YELLOW_ORANGE")
	if _, err := p1.Encrypt(d1, nil); err != nil {
		t.Fatalf("p1.Encrypt() err = %v, want nil", err)
	}
	d2 := []byte("ORANGE_BLUE")
	if _, err := p2.Encrypt(d2, nil); err != nil {
		t.Fatalf("p2.Encrypt() err = %v, want nil", err)
	}
	got := client.Events()
	want := []*fakemonitoring.LogEvent{
		{
			KeyID:    kh1.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(d1),
			Context: monitoring.NewContext(
				"aead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh1.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh1.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesGcmKey",
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
				"aead",
				"encrypt",
				monitoring.NewKeysetInfo(
					annotations,
					kh2.KeysetInfo().GetPrimaryKeyId(),
					[]*monitoring.Entry{
						{
							KeyID:     kh2.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.AesCtrHmacAeadKey",
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

func TestPrimitiveFactoryEncryptDecryptWithoutAnnotationsDoesNothing(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	p, err := aead.New(kh)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	data := []byte("YELLOW_ORANGE")
	ct, err := p.Encrypt(data, nil)
	if err != nil {
		t.Fatalf("p.Encrypt() err = %v, want nil", err)
	}
	if _, err := p.Decrypt(ct, nil); err != nil {
		t.Fatalf("p.Decrypt() err = %v, want nil", err)
	}
	got := client.Events()
	if len(got) != 0 {
		t.Errorf("len(client.Events()) = %d, want 0", len(got))
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
}
