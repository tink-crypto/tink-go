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

package factoryutil_test

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func mustCreateHMACKey(variant hmac.Variant, idRequirement uint32) key.Key {
	hmacParams, err := hmac.NewParameters(hmac.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		HashType:       hmac.SHA256,
		Variant:        variant,
	})
	if err != nil {
		panic(err)
	}
	keyBytes, err := secretdata.NewBytesFromRand(32)
	if err != nil {
		panic(err)
	}
	hmacKey, err := hmac.NewKey(keyBytes, hmacParams, idRequirement)
	if err != nil {
		panic(err)
	}
	return hmacKey
}

func TestLoggerBuilder_CreatesLoggerWithContext(t *testing.T) {
	internalregistry.ClearMonitoringClient()
	fakeClient := fakemonitoring.NewClient("fake")
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("RegisterMonitoringClient() err = %v, want nil", err)
	}
	defer internalregistry.ClearMonitoringClient()

	annotations := map[string]string{"foo": "bar"}
	manager := keyset.NewManager()
	_, err := manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 1), internalapi.Token{}, keyset.AsPrimary())
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 2), internalapi.Token{}, keyset.WithStatus(keyset.Disabled))
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	keyID, err := manager.AddKey(mustCreateHMACKey(hmac.VariantNoPrefix, 0))
	if err != nil {
		t.Fatalf("AddKey() err = %v, want nil", err)
	}
	if err := manager.SetAnnotations(annotations); err != nil {
		t.Fatalf("SetAnnotations() err = %v, want nil", err)
	}
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("Handle() err = %v, want nil", err)
	}

	builder, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		t.Fatalf("NewLoggerFactory() err = %v, want nil", err)
	}

	logger, err := builder.CreateFor("mac", "compute")
	if err != nil {
		t.Fatalf("CreateFor() err = %v, want nil", err)
	}

	logger.Log(1, 42)
	events := fakeClient.Events()
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}

	wantContext := &monitoring.Context{
		Primitive:   "mac",
		APIFunction: "compute",
		KeysetInfo: &monitoring.KeysetInfo{
			Annotations:  annotations,
			PrimaryKeyID: 1,
			Entries: []*monitoring.Entry{
				{
					Status:    monitoring.Enabled,
					KeyID:     1,
					KeyType:   "tink.HmacKey",
					KeyPrefix: "TINK",
				},
				{
					Status:    monitoring.Enabled,
					KeyID:     keyID,
					KeyType:   "tink.HmacKey",
					KeyPrefix: "RAW",
				},
			},
		},
	}

	if diff := cmp.Diff(events[0].Context, wantContext); diff != "" {
		t.Errorf("Logger context mismatch (-want +got): %s", diff)
	}
}

func TestLoggerBuilder_WithoutAnnotations(t *testing.T) {
	internalregistry.ClearMonitoringClient()
	fakeClient := fakemonitoring.NewClient("fake")
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("RegisterMonitoringClient() err = %v, want nil", err)
	}
	defer internalregistry.ClearMonitoringClient()

	manager := keyset.NewManager()
	_, err := manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 1), internalapi.Token{}, keyset.AsPrimary())
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 2), internalapi.Token{}, keyset.WithStatus(keyset.Disabled))
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKey(mustCreateHMACKey(hmac.VariantNoPrefix, 0))
	if err != nil {
		t.Fatalf("AddKey() err = %v, want nil", err)
	}
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("Handle() err = %v, want nil", err)
	}

	builder, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		t.Fatalf("NewLoggerFactory() err = %v, want nil", err)
	}

	logger, err := builder.CreateFor("mac", "compute")
	if err != nil {
		t.Fatalf("CreateFor() err = %v, want nil", err)
	}

	if _, ok := logger.(*monitoringutil.DoNothingLogger); !ok {
		t.Errorf("logger is %T, want *monitoringutil.DoNothingLogger", logger)
	}
}

func TestLoggerBuilder_NoClientReturnsDoNothingLogger(t *testing.T) {
	internalregistry.ClearMonitoringClient()

	annotations := map[string]string{"foo": "bar"}
	manager := keyset.NewManager()
	_, err := manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 1), internalapi.Token{}, keyset.AsPrimary())
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 2), internalapi.Token{}, keyset.WithStatus(keyset.Disabled))
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKey(mustCreateHMACKey(hmac.VariantNoPrefix, 0))
	if err != nil {
		t.Fatalf("AddKey() err = %v, want nil", err)
	}
	if err := manager.SetAnnotations(annotations); err != nil {
		t.Fatalf("SetAnnotations() err = %v, want nil", err)
	}
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("Handle() err = %v, want nil", err)
	}

	builder, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		t.Fatalf("NewLoggerFactory() err = %v, want nil", err)
	}

	logger, err := builder.CreateFor("mac", "compute")
	if err != nil {
		t.Fatalf("CreateFor() err = %v, want nil", err)
	}

	if _, ok := logger.(*monitoringutil.DoNothingLogger); !ok {
		t.Errorf("logger is %T, want *monitoringutil.DoNothingLogger", logger)
	}
}

func TestEnabledUnmonitoredEntries(t *testing.T) {
	internalregistry.ClearMonitoringClient()
	fakeClient := fakemonitoring.NewClient("fake")
	if err := internalregistry.RegisterMonitoringClient(fakeClient); err != nil {
		t.Fatalf("RegisterMonitoringClient() err = %v, want nil", err)
	}
	defer internalregistry.ClearMonitoringClient()

	manager := keyset.NewManager()
	_, err := manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 1), internalapi.Token{}, keyset.AsPrimary())
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantTink, 2), internalapi.Token{}, keyset.WithStatus(keyset.Disabled))
	if err != nil {
		t.Fatalf("AddKeyWithOpts() err = %v, want nil", err)
	}
	_, err = manager.AddKeyWithOpts(mustCreateHMACKey(hmac.VariantNoPrefix, 0), internalapi.Token{}, keyset.WithFixedID(1234))
	if err != nil {
		t.Fatalf("AddKey() err = %v, want nil", err)
	}
	if err := manager.SetAnnotations(map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("SetAnnotations() err = %v, want nil", err)
	}
	kh, err := manager.Handle()
	if err != nil {
		t.Fatalf("Handle() err = %v, want nil", err)
	}

	var got []uint32
	for entry := range factoryutil.EnabledUnmonitoredEntries(kh) {
		got = append(got, entry.KeyID())
	}
	want := []uint32{1, 1234}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("EnabledUnmonitoredEntries() mismatch (-want +got): %s", diff)
	}
	if len(fakeClient.KeyExportsLogs()) != 0 {
		t.Errorf("KeyExportsLogs() = %d, want 0", len(fakeClient.KeyExportsLogs()))
	}
}

func TestEnabledUnmonitoredEntries_Empty(t *testing.T) {
	var got []uint32
	for entry := range factoryutil.EnabledUnmonitoredEntries(nil) {
		got = append(got, entry.KeyID())
	}
	if len(got) != 0 {
		t.Errorf("EnabledUnmonitoredEntries() = %d, want 0", len(got))
	}
}

func TestPrimitiveFromKey_Full(t *testing.T) {
	primitive := "primitive"
	cb := config.NewBuilder()
	if err := cb.RegisterPrimitiveConstructor(reflect.TypeFor[*hmac.Key](), func(key key.Key) (any, error) {
		return primitive, nil
	}, internalapi.Token{}); err != nil {
		t.Fatalf("cb.RegisterPrimitiveConstructor() err = %v, want nil", err)
	}
	config := cb.Build()
	key := mustCreateHMACKey(hmac.VariantTink, 1)
	got, isLegacy, err := factoryutil.PrimitiveFromKey[string](key, &config)
	if err != nil {
		t.Fatalf("PrimitiveFromKey() err = %v, want nil", err)
	}
	if diff := cmp.Diff(primitive, got); diff != "" || isLegacy {
		t.Errorf("PrimitiveFromKey() mismatch (-want +got): %s", diff)
	}

	// Try to create a primitive of the wrong type.
	_, _, err = factoryutil.PrimitiveFromKey[int](key, &config)
	if err == nil {
		t.Errorf("PrimitiveFromKey() err = nil, want error")
	}
}

func TestPrimitiveFromKey_Legacy(t *testing.T) {
	// RegistryConfig is the only config that can create legacy primitives.
	config := registryconfig.RegistryConfig{}

	// Artificially unregister the primitive constructor to force the legacy path.
	primitiveregistry.UnregisterPrimitiveConstructor[*hmac.Key]()

	key := mustCreateHMACKey(hmac.VariantTink, 1)
	m, isLegacy, err := factoryutil.PrimitiveFromKey[tink.MAC](key, &config)
	if err != nil {
		t.Fatalf("PrimitiveFromKey() err = %v, want nil", err)
	}
	if !isLegacy {
		t.Errorf("PrimitiveFromKey() isLegacy = false, want true")
	}

	d, err := m.ComputeMAC([]byte("data"))
	if err != nil {
		t.Fatalf("ComputeMAC() err = %v, want nil", err)
	}
	if err := m.VerifyMAC(d, []byte("data")); err != nil {
		t.Errorf("VerifyMAC() err = %v, want nil", err)
	}
}

func TestOutputPrefix(t *testing.T) {
	key := mustCreateHMACKey(hmac.VariantTink, 1)
	got, err := factoryutil.OutputPrefix(key)
	if err != nil {
		t.Fatalf("OutputPrefix() err = %v, want nil", err)
	}
	if diff := cmp.Diff([]byte{cryptofmt.TinkStartByte, 0, 0, 0, 1}, got); diff != "" {
		t.Errorf("OutputPrefix() mismatch (-want +got): %s", diff)
	}
}

func TestOutputPrefix_NoPrefix(t *testing.T) {
	key := mustCreateHMACKey(hmac.VariantNoPrefix, 0)
	got, err := factoryutil.OutputPrefix(key)
	if err != nil {
		t.Fatalf("OutputPrefix() err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("OutputPrefix() = %v, want nil", got)
	}
}

type noOutputPrefixParameters struct{}

func (p *noOutputPrefixParameters) HasIDRequirement() bool { return false }

func (p *noOutputPrefixParameters) Equal(other key.Parameters) bool { return false }

type noOutputPrefixKey struct{}

func (k *noOutputPrefixKey) Parameters() key.Parameters {
	return &noOutputPrefixParameters{}
}
func (k *noOutputPrefixKey) IDRequirement() (idRequirement uint32, required bool) { return 0, false }

func (k *noOutputPrefixKey) Equal(other key.Key) bool { return false }

func TestOutputPrefix_DoesNotHaveOutputPrefix(t *testing.T) {
	if _, err := factoryutil.OutputPrefix(&noOutputPrefixKey{}); err == nil {
		t.Errorf("OutputPrefix() err = nil, want error")
	}
}
