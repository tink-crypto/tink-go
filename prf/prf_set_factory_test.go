// Copyright 2020 Google LLC
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

package prf_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/testutil"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const (
	maxAutocorrelation = 100
)

func addKeyAndReturnID(m *keyset.Manager, template *tinkpb.KeyTemplate) (uint32, error) {
	keyID, err := m.Add(template)
	if err != nil {
		return 0, fmt.Errorf("Could not add key from the given template: %v", err)
	}
	err = m.SetPrimary(keyID)
	if err != nil {
		return 0, fmt.Errorf("Could set key as primary: %v", err)
	}
	return keyID, nil
}

func TestFactoryBasic(t *testing.T) {
	manager := keyset.NewManager()
	aescmacID, err := addKeyAndReturnID(manager, prf.AESCMACPRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add AES CMAC PRF key: %v", err)
	}

	hmacsha256ID, err := addKeyAndReturnID(manager, prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HMAC SHA256 PRF key: %v", err)
	}
	hkdfsha256ID, err := addKeyAndReturnID(manager, prf.HKDFSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HKDF SHA256 PRF key: %v", err)
	}
	hmacsha512ID, err := addKeyAndReturnID(manager, prf.HMACSHA512PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HMAC SHA512 PRF key: %v", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Errorf("Could not obtain handle: %v", err)
	}
	prfSet, err := prf.NewPRFSet(handle)
	if err != nil {
		t.Errorf("Could not create prf.Set with standard key templates: %v", err)
	}
	primaryID := prfSet.PrimaryID
	if primaryID != hmacsha512ID {
		t.Errorf("Primary ID %d should be the ID %d, which was added last", primaryID, hmacsha512ID)
	}
	for _, length := range []uint32{1, 10, 16, 17, 32, 33, 64, 65, 100, 8160, 8161} {
		results := [][]byte{}
		for id, prf := range prfSet.PRFs {
			ok := true
			switch {
			case length > 16 && id == aescmacID:
				ok = false
			case length > 32 && id == hmacsha256ID:
				ok = false
			case length > 64 && id == hmacsha512ID:
				ok = false
			case length > 8160 && id == hkdfsha256ID:
				ok = false
			}

			result1, err := prf.ComputePRF([]byte("The input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			result2, err := prf.ComputePRF([]byte("The different input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			result3, err := prf.ComputePRF([]byte("The input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			if id == primaryID {
				primaryResult, err := prfSet.ComputePrimaryPRF([]byte("The input"), length)
				switch {
				case err != nil && !ok:
					continue
				case err != nil:
					t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
					continue
				case !ok:
					t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
					continue
				}
				if hex.EncodeToString(result1) != hex.EncodeToString(primaryResult) {
					t.Errorf("Expected manual call of ComputePRF of primary PRF and ComputePrimaryPRF with the same input to produce the same output, but got %q and %q", result1, primaryResult)
				}
			}
			if hex.EncodeToString(result1) != hex.EncodeToString(result3) {
				t.Errorf("Expected different calls with the same input to produce the same output, but got %q and %q", result1, result3)
			}
			results = append(results, result1)
			results = append(results, result2)
		}
		runZTests(results, t)
	}
}

func TestNonPRFPrimitives(t *testing.T) {
	template := mac.AESCMACTag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	h, err := keyset.NewHandle(template)
	if err != nil {
		t.Errorf("Couldn't create keyset: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected non PRF primitive to fail to create prf.Set")
	}
	m := keyset.NewManagerFromHandle(h)
	_, err = addKeyAndReturnID(m, prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Expected to be able to add keys to the keyset: %v", err)
	}
	h, err = m.Handle()
	if err != nil {
		t.Errorf("Expected to be able to create keyset handle: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected mixed primitive keyset to fail to create prf.Set")
	}
}

func runZTests(results [][]byte, t *testing.T) {
	for i, result1 := range results {
		if err := testutil.ZTestUniformString(result1); err != nil {
			t.Errorf("Expected PRF output to pass uniformity z test: %v", err)
		}
		if len(result1) <= maxAutocorrelation {
			if err := testutil.ZTestAutocorrelationUniformString(result1); err != nil {
				t.Errorf("Expected PRF output to pass autocorrelation test: %v", err)
			}
		}
		for j := i + 1; j < len(results); j++ {
			result2 := results[j]
			if err := testutil.ZTestCrosscorrelationUniformStrings(result1, result2); err != nil {
				t.Errorf("Expected different PRF outputs to be uncorrelated: %v", err)
			}
		}
	}
}

func TestPrimitiveFactoryComputePRFWithoutAnnotationsDoesNothing(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	prfSet, err := prf.NewPRFSet(kh)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	if _, err := prfSet.ComputePrimaryPRF([]byte("input_data"), 32); err != nil {
		t.Fatalf("prfSet.ComputePrimaryPRF() err = %v, want nil", err)
	}
	failures := len(client.Failures())
	if failures != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", failures)
	}
	got := client.Events()
	if got != nil {
		t.Errorf("client.Events() = %v, want nil", got)
	}
}

func TestPrimitiveFactoryMonitoringWithAnnotationsComputePRFFailureIsLogged(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	prfSet, err := prf.NewPRFSet(mh)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	data := []byte("input_data")
	if _, err := prfSet.ComputePrimaryPRF(data, 64); err == nil {
		t.Fatalf("prfSet.ComputePrimaryPRF() err = nil, want non-nil errors")
	}
	got := client.Failures()
	want := []*fakemonitoring.LogFailure{
		{
			Context: monitoring.NewContext(
				"prf",
				"compute",
				&monitoring.KeysetInfo{
					Annotations: annotations,
					Entries: []*monitoring.Entry{
						{
							KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
							Status:    monitoring.Enabled,
							KeyType:   "tink.HmacPrfKey",
							KeyPrefix: "RAW",
						},
					},
					PrimaryKeyID: kh.KeysetInfo().GetPrimaryKeyId(),
				},
			),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%v", diff)
	}
}

func TestPrimitiveFactoryIndividualPrfWithAnnotatonsLogsCompute(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	manager := keyset.NewManagerFromHandle(kh)
	hmac512KeyID, err := manager.Add(prf.HMACSHA512PRFKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add() err = %v, want nil", err)
	}
	aesKeyID, err := manager.Add(prf.AESCMACPRFKeyTemplate())
	if err != nil {
		t.Fatalf("manager.Add() err = %v, want nil", err)
	}
	kh, err = manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	prfSet, err := prf.NewPRFSet(mh)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	for _, p := range prfSet.PRFs {
		if _, err := p.ComputePRF([]byte("input_data"), 16); err != nil {
			t.Fatalf("p.ComputePRF() err = %v, want nil", err)
		}

	}
	got := client.Events()
	wantKeysetInfo := &monitoring.KeysetInfo{
		PrimaryKeyID: kh.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacPrfKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     hmac512KeyID,
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacPrfKey",
				KeyPrefix: "RAW",
			},
			{
				KeyID:     aesKeyID,
				Status:    monitoring.Enabled,
				KeyType:   "tink.AesCmacPrfKey",
				KeyPrefix: "RAW",
			},
		},
		Annotations: annotations,
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("prf", "compute", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetKeyInfo()[0].GetKeyId(),
			NumBytes: len("input_data"),
		},
		{
			Context:  monitoring.NewContext("prf", "compute", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetKeyInfo()[1].GetKeyId(),
			NumBytes: len("input_data"),
		},
		{
			Context:  monitoring.NewContext("prf", "compute", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetKeyInfo()[2].GetKeyId(),
			NumBytes: len("input_data"),
		},
	}
	eventCmp := func(a, b *fakemonitoring.LogEvent) bool {
		return a.KeyID < b.KeyID
	}
	if !cmp.Equal(got, want, cmpopts.SortSlices(eventCmp)) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}

}

func TestPrimitiveFactoryWithMonitoringAnnotationsLogsComputePRF(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}
	kh, err := keyset.NewHandle(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	mh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}
	prfSet, err := prf.NewPRFSet(mh)
	if err != nil {
		t.Fatalf("prf.NewPRFSet() err = %v, want nil", err)
	}
	data := []byte("some_data")
	if _, err := prfSet.ComputePrimaryPRF(data, 20); err != nil {
		t.Fatalf("prfSet.ComputePrimaryPRF() err = %v, want nil", err)
	}
	got := client.Events()
	wantKeysetInfo := &monitoring.KeysetInfo{
		PrimaryKeyID: kh.KeysetInfo().GetPrimaryKeyId(),
		Entries: []*monitoring.Entry{
			{
				KeyID:     kh.KeysetInfo().GetPrimaryKeyId(),
				Status:    monitoring.Enabled,
				KeyType:   "tink.HmacPrfKey",
				KeyPrefix: "RAW",
			},
		},
		Annotations: annotations,
	}
	want := []*fakemonitoring.LogEvent{
		{
			Context:  monitoring.NewContext("prf", "compute", wantKeysetInfo),
			KeyID:    kh.KeysetInfo().GetPrimaryKeyId(),
			NumBytes: len(data),
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}

const keyURL = "type.googleapis.com/google.crypto.tink.KeyURL"

type stubParams struct{}

var _ key.Parameters = (*stubParams)(nil)

func (p *stubParams) Equal(_ key.Parameters) bool { return true }
func (p *stubParams) HasIDRequirement() bool      { return true }

type stubKey struct{}

var _ key.Key = (*stubKey)(nil)

func (p *stubKey) Equal(_ key.Key) bool          { return true }
func (p *stubKey) Parameters() key.Parameters    { return &stubParams{} }
func (p *stubKey) IDRequirement() (uint32, bool) { return 0, false }
func (p *stubKey) HasIDRequirement() bool        { return false }
func (p *stubKey) OutputPrefix() []byte          { return nil }

type stubKeySerialization struct{}

var _ protoserialization.KeySerializer = (*stubKeySerialization)(nil)

func (s *stubKeySerialization) SerializeKey(key key.Key) (*protoserialization.KeySerialization, error) {
	return protoserialization.NewKeySerialization(
		&tinkpb.KeyData{
			TypeUrl:         keyURL,
			Value:           []byte("serialized_key"),
			KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		},
		tinkpb.OutputPrefixType_RAW,
		0,
	)
}

type stubKeyParser struct{}

var _ protoserialization.KeyParser = (*stubKeyParser)(nil)

func (s *stubKeyParser) ParseKey(serialization *protoserialization.KeySerialization) (key.Key, error) {
	return &stubKey{}, nil
}

type stubFullPRF struct{}

var _ prf.PRF = (*stubFullPRF)(nil)

func (s *stubFullPRF) ComputePRF(input []byte, outputLength uint32) ([]byte, error) {
	return slices.Concat([]byte("full_primitive"), input, []byte(strconv.Itoa(int(outputLength)))), nil
}

type legacyPRF struct{}

var _ prf.PRF = (*legacyPRF)(nil)

func (s *legacyPRF) ComputePRF(input []byte, outputLength uint32) ([]byte, error) {
	return slices.Concat([]byte("legacy_primitive"), input, []byte(strconv.Itoa(int(outputLength)))), nil
}

func TestNewWithConfig(t *testing.T) {
	defer protoserialization.UnregisterKeyParser(keyURL)
	defer protoserialization.UnregisterKeySerializer[*stubKey]()
	if err := protoserialization.RegisterKeyParser(keyURL, &stubKeyParser{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeyParser() err = %v, want nil", err)
	}
	if err := protoserialization.RegisterKeySerializer[*stubKey](&stubKeySerialization{}); err != nil {
		t.Fatalf("protoserialization.RegisterKeySerializer() err = %v, want nil", err)
	}

	configBuilder := config.NewBuilder()
	if err := configBuilder.RegisterPrimitiveConstructor(reflect.TypeFor[*stubKey](), func(key key.Key) (any, error) { return &stubFullPRF{}, nil }, internalapi.Token{}); err != nil {
		t.Fatalf("configBuilder.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	config := configBuilder.Build()

	km := keyset.NewManager()
	if _, err := km.AddKeyWithOpts(&stubKey{}, internalapi.Token{}, keyset.AsPrimary()); err != nil {
		t.Fatalf("km.AddKey() err = %v, want nil", err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}

	prfSet, err := prf.NewPRFSetWithConfig(handle, &config)
	if err != nil {
		t.Fatalf("prf.NewPRFSetWithConfig() err = %v, want nil", err)
	}
	out, err := prfSet.ComputePrimaryPRF([]byte("message"), 10)
	if err != nil {
		t.Fatalf("prfSet.ComputePrimaryPRF() err = %v, want nil", err)
	}
	if !bytes.HasPrefix(out, []byte("full_primitive")) {
		t.Errorf("out = %q, want prefix: %q", out, []byte("full_primitive"))
	}
}
