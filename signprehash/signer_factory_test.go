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
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signprehash"
	"github.com/tink-crypto/tink-go/v2/testing/fakemonitoring"
)

func TestNewPrehashSignerFailsWithNilHandle(t *testing.T) {
	if _, err := signprehash.NewPrehashSigner(nil); err == nil {
		t.Errorf("signprehash.NewPrehashSigner(nil) err = nil, want error")
	} else if !strings.Contains(err.Error(), "handle cannot be nil") {
		t.Errorf("signprehash.NewPrehashSigner(nil) err = %v, want error containing 'handle cannot be nil'", err)
	}
}

func TestNewPrehashSignerFailsWithNoPrimaryKey(t *testing.T) {
	emptyHandle := &keyset.Handle{}
	if _, err := signprehash.NewPrehashSigner(emptyHandle); err == nil {
		t.Errorf("signprehash.NewPrehashSigner(emptyHandle) err = nil, want error")
	} else if !strings.Contains(err.Error(), "empty keyset handle") && !strings.Contains(err.Error(), "failed to get primary entry") {
		t.Errorf("signprehash.NewPrehashSigner() err = %v, want error containing 'empty keyset handle'", err)
	}
}

func TestNewPrehashSignerFailsWithUnsupportedKeyType(t *testing.T) {
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}

	if _, err := signprehash.NewPrehashSigner(handle); err == nil {
		t.Errorf("signprehash.NewPrehashSigner(HMAC handle) err = nil, want error")
	} else if !strings.Contains(err.Error(), "failed to get primitive for primary key") {
		t.Errorf("signprehash.NewPrehashSigner(HMAC handle) err = %v, want error containing 'failed to get primitive for primary key'", err)
	}
}

func TestSignPrehashFailureModes(t *testing.T) {
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefixWithPrehashID)
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
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	prehashSigner, err := signprehash.NewPrehashSigner(privHandle)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	validPrehash, err := prehasher.ComputePrehash([]byte("test message"))
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}

	// 1. Short prehash payload (length < 5)
	if _, err := prehashSigner.SignPrehash(validPrehash[:3]); err == nil {
		t.Errorf("SignPrehash(short) err = nil, want error")
	}

	// 2. Invalid start byte
	invalidStartByte := make([]byte, len(validPrehash))
	copy(invalidStartByte, validPrehash)
	invalidStartByte[0] = 0x00
	if _, err := prehashSigner.SignPrehash(invalidStartByte); err == nil {
		t.Errorf("SignPrehash(invalidStartByte) err = nil, want error")
	}

	// 3. Mismatched key ID
	mismatchedKeyIDPrehash := make([]byte, len(validPrehash))
	copy(mismatchedKeyIDPrehash, validPrehash)
	binary.BigEndian.PutUint32(mismatchedKeyIDPrehash[1:5], keyID^0xffffffff)
	if _, err := prehashSigner.SignPrehash(mismatchedKeyIDPrehash); err == nil {
		t.Errorf("SignPrehash(mismatchedKeyID) err = nil, want error")
	}
}

func TestNewPrehashSignerSucceeds(t *testing.T) {
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
				t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
			}
			prehashSigner, err := signprehash.NewPrehashSigner(privHandle)
			if err != nil {
				t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
			}

			entry, err := pubHandle.Primary()
			if err != nil {
				t.Fatalf("pubHandle.Primary() err = %v, want nil", err)
			}
			verifier, err := tinkmldsa.NewVerifier(entry.Key().(*tinkmldsa.PublicKey), internalapi.Token{})
			if err != nil {
				t.Fatalf("tinkmldsa.NewVerifier() err = %v, want nil", err)
			}

			msg := []byte("sample message for signer factory test")
			prehash, err := prehasher.ComputePrehash(msg)
			if err != nil {
				t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
			}

			sig, err := prehashSigner.SignPrehash(prehash)
			if err != nil {
				t.Fatalf("prehashSigner.SignPrehash() err = %v, want nil", err)
			}

			if err := verifier.Verify(sig, msg); err != nil {
				t.Errorf("verifier.Verify(sig, msg) err = %v, want nil", err)
			}
		})
	}
}

func TestPrehashSignerFactoryMonitoring(t *testing.T) {
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
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buff)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	annotations := map[string]string{"foo": "bar"}
	handleWithAnnotations, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(buff), keyset.WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	prehasher, err := signprehash.NewPrehash(pubHandle)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	prehashSigner, err := signprehash.NewPrehashSigner(handleWithAnnotations)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	data := []byte("sample data for monitoring test")
	prehash, err := prehasher.ComputePrehash(data)
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}
	if _, err := prehashSigner.SignPrehash(prehash); err != nil {
		t.Fatalf("prehashSigner.SignPrehash() err = %v, want nil", err)
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
	if gotEvents[0].NumBytes != len(prehash) {
		t.Errorf("gotEvents[0].NumBytes = %d, want %d", gotEvents[0].NumBytes, len(prehash))
	}
}
