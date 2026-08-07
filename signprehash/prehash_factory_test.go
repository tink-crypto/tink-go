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

package signprehash_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signprehash"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
)

func TestNewPrehashFailsWithNilHandle(t *testing.T) {
	if _, err := signprehash.NewPrehash(nil); err == nil {
		t.Errorf("signprehash.NewPrehash(nil) err = nil, want error")
	} else if !strings.Contains(err.Error(), "handle cannot be nil") {
		t.Errorf("signprehash.NewPrehash(nil) err = %v, want error containing 'handle cannot be nil'", err)
	}
}

func TestNewPrehashFailsWithUnsupportedKeyType(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}

	if _, err := signprehash.NewPrehash(handle); err == nil {
		t.Errorf("signprehash.NewPrehash(HMAC handle) err = nil, want error")
	} else if !strings.Contains(err.Error(), "failed to get primitive for primary key") {
		t.Errorf("signprehash.NewPrehash(HMAC handle) err = %v, want error containing 'failed to get primitive for primary key'", err)
	}
}

func TestNewPrehashFailsWithVariantNoPrefix(t *testing.T) {
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary() err = %v, want nil", err)
	}
	privHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	pubHandle, err := privHandle.Public()
	if err != nil {
		t.Fatalf("privHandle.Public() err = %v, want nil", err)
	}

	if _, err := signprehash.NewPrehash(pubHandle); err == nil {
		t.Errorf("signprehash.NewPrehash(VariantNoPrefix handle) err = nil, want error")
	} else if !strings.Contains(err.Error(), "must not be VariantNoPrefix") {
		t.Errorf("signprehash.NewPrehash(VariantNoPrefix handle) err = %v, want error containing 'must not be VariantNoPrefix'", err)
	}
}

func TestNewPrehashSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance tinkmldsa.Instance
		variant  tinkmldsa.Variant
	}{
		{
			name:     "ML-DSA-44 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA44,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
		},
		{
			name:     "ML-DSA-65 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
		},
		{
			name:     "ML-DSA-87 NoPrefixWithPrehashID",
			instance: tinkmldsa.MLDSA87,
			variant:  tinkmldsa.VariantNoPrefixWithPrehashID,
		},
		{
			name:     "ML-DSA-65 Tink variant",
			instance: tinkmldsa.MLDSA65,
			variant:  tinkmldsa.VariantTink,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := tinkmldsa.NewParameters(tc.instance, tc.variant)
			if err != nil {
				t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
			}
			manager := keyset.NewManager()
			keyID, err := manager.AddNewKeyFromParameters(params)
			if err != nil {
				t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
			}
			if err := manager.SetPrimary(keyID); err != nil {
				t.Fatalf("manager.SetPrimary() err = %v, want nil", err)
			}
			privHandle, err := manager.Handle()
			if err != nil {
				t.Fatalf("manager.Handle() err = %v, want nil", err)
			}
			pubHandle, err := privHandle.Public()
			if err != nil {
				t.Fatalf("privHandle.Public() err = %v, want nil", err)
			}

			prehasher, err := signprehash.NewPrehash(pubHandle)
			if err != nil {
				t.Fatalf("signprehash.NewPrehash(pubHandle) err = %v, want nil", err)
			}

			data := []byte("sample data for prehash factory test")
			prehash, err := prehasher.ComputePrehash(data)
			if err != nil {
				t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
			}
			if len(prehash) != 5+64 {
				t.Errorf("len(prehash) = %d, want %d", len(prehash), 5+64)
			}
		})
	}
}

func TestPrehashFactoryMonitoring(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantTink)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary() err = %v, want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	pubHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}

	buff := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(pubHandle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	pubHandleWithAnnotations, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	prehasher, err := signprehash.NewPrehash(pubHandleWithAnnotations)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}

	data := []byte("sample data for monitoring test")
	if _, err := prehasher.ComputePrehash(data); err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}

	if len(client.Failures()) != 0 {
		t.Errorf("len(client.Failures()) = %d, want 0", len(client.Failures()))
	}
	gotEvents := client.Events()
	if len(gotEvents) != 1 {
		t.Fatalf("len(gotEvents) = %d, want 1", len(gotEvents))
	}
	if gotEvents[0].KeyID != keyID {
		t.Errorf("gotEvents[0].KeyID = %d, want %d", gotEvents[0].KeyID, keyID)
	}
	if gotEvents[0].NumBytes != len(data) {
		t.Errorf("gotEvents[0].NumBytes = %d, want %d", gotEvents[0].NumBytes, len(data))
	}
}
