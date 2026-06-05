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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac/hmac"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
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
