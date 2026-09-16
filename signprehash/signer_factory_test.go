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
	"github.com/tink-crypto/tink-go/v2/signature"
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
	} else if !strings.Contains(err.Error(), "failed to get primitive for key") {
		t.Errorf("signprehash.NewPrehashSigner(HMAC handle) err = %v, want error containing 'failed to get primitive for key'", err)
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

// rotationSetup builds a two key ML-DSA keyset in the state a keyset is in
// midway through a rotation: both keys enabled, the new key promoted to
// primary, while prehash values naming the old key are still arriving.
//
// It returns the private keyset, whose primary is newID, and the public keyset
// as it looked before the promotion, which holds oldID alone. The latter stands
// in for a prehashing side that has not picked up the new key yet.
func rotationSetup(t *testing.T) (privHandleAfterRotation, pubHandleBeforeRotation *keyset.Handle, oldID, newID uint32) {
	t.Helper()
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefixWithPrehashID)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	oldID, err = manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := manager.SetPrimary(oldID); err != nil {
		t.Fatalf("manager.SetPrimary(oldID) err = %v, want nil", err)
	}

	// Take the public keyset before the new key exists, so that it names the
	// old key and nothing else.
	privHandleBeforeRotation, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	pubHandleBeforeRotation, err = privHandleBeforeRotation.Public()
	if err != nil {
		t.Fatalf("privHandleBeforeRotation.Public() err = %v, want nil", err)
	}

	newID, err = manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if newID == oldID {
		t.Fatalf("manager.AddNewKeyFromParameters() reused key ID %d, want a distinct one", oldID)
	}
	if err := manager.SetPrimary(newID); err != nil {
		t.Fatalf("manager.SetPrimary(newID) err = %v, want nil", err)
	}
	privHandleAfterRotation, err = manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	return privHandleAfterRotation, pubHandleBeforeRotation, oldID, newID
}

// TestSignPrehashSignsWithNonPrimaryEnabledKey pins the key selection contract:
// SignPrehash signs with the enabled key the prehash value names, even when that
// key is not the primary key.
//
// Binding the signer to the primary key instead makes a keyset un-rotatable. The
// prehashing and signing sides cannot promote a new key at the same instant, so
// whichever side promotes first would produce or receive prehash values the
// other side rejects, and every prehash value in flight across the promotion
// would be lost. C++ and Java route by key ID for this reason.
func TestSignPrehashSignsWithNonPrimaryEnabledKey(t *testing.T) {
	privHandleAfterRotation, pubHandleBeforeRotation, oldID, _ := rotationSetup(t)

	prehasher, err := signprehash.NewPrehash(pubHandleBeforeRotation)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	signer, err := signprehash.NewPrehashSigner(privHandleAfterRotation)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	msg := []byte("message prehashed before the new key was promoted")
	prehash, err := prehasher.ComputePrehash(msg)
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}
	if got := binary.BigEndian.Uint32(prehash[1:5]); got != oldID {
		t.Fatalf("prehash names key ID %d, want %d", got, oldID)
	}

	sig, err := signer.SignPrehash(prehash)
	if err != nil {
		t.Fatalf("signer.SignPrehash() err = %v, want nil", err)
	}

	// The result is an ordinary signature over msg under the old key, so it
	// verifies for a relying party that has not picked up the new key as well as
	// for one that has.
	pubHandleAfterRotation, err := privHandleAfterRotation.Public()
	if err != nil {
		t.Fatalf("privHandleAfterRotation.Public() err = %v, want nil", err)
	}
	for _, tc := range []struct {
		name   string
		public *keyset.Handle
	}{
		{"public keyset before the rotation", pubHandleBeforeRotation},
		{"public keyset after the rotation", pubHandleAfterRotation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, err := signature.NewVerifier(tc.public)
			if err != nil {
				t.Fatalf("signature.NewVerifier() err = %v, want nil", err)
			}
			if err := verifier.Verify(sig, msg); err != nil {
				t.Errorf("verifier.Verify(sig, msg) err = %v, want nil", err)
			}
		})
	}
}

// TestSignPrehashFailsForDisabledKey checks that the key selection is restricted
// to enabled keys, so that disabling a key actually retires it.
func TestSignPrehashFailsForDisabledKey(t *testing.T) {
	privHandleAfterRotation, pubHandleBeforeRotation, oldID, _ := rotationSetup(t)
	manager := keyset.NewManagerFromHandle(privHandleAfterRotation)
	if err := manager.Disable(oldID); err != nil {
		t.Fatalf("manager.Disable(oldID) err = %v, want nil", err)
	}
	privWithOldDisabled, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	prehasher, err := signprehash.NewPrehash(pubHandleBeforeRotation)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	signer, err := signprehash.NewPrehashSigner(privWithOldDisabled)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	prehash, err := prehasher.ComputePrehash([]byte("message for a disabled key"))
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}
	if _, err := signer.SignPrehash(prehash); err == nil {
		t.Errorf("signer.SignPrehash(prehash for disabled key) err = nil, want error")
	} else if !strings.Contains(err.Error(), "no enabled key") {
		t.Errorf("signer.SignPrehash() err = %v, want error containing 'no enabled key'", err)
	}
}

// TestSignPrehashFailsForAbsentKey checks that a prehash value naming a key the
// keyset does not hold is rejected rather than signed with some other key.
func TestSignPrehashFailsForAbsentKey(t *testing.T) {
	privHandleAfterRotation, pubHandleBeforeRotation, oldID, _ := rotationSetup(t)
	manager := keyset.NewManagerFromHandle(privHandleAfterRotation)
	if err := manager.Delete(oldID); err != nil {
		t.Fatalf("manager.Delete(oldID) err = %v, want nil", err)
	}
	privWithOldDeleted, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	prehasher, err := signprehash.NewPrehash(pubHandleBeforeRotation)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	signer, err := signprehash.NewPrehashSigner(privWithOldDeleted)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	prehash, err := prehasher.ComputePrehash([]byte("message for a deleted key"))
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}
	if _, err := signer.SignPrehash(prehash); err == nil {
		t.Errorf("signer.SignPrehash(prehash for absent key) err = nil, want error")
	} else if !strings.Contains(err.Error(), "no enabled key") {
		t.Errorf("signer.SignPrehash() err = %v, want error containing 'no enabled key'", err)
	}
}

// TestPrehashSignerMonitoringLogsSigningKey checks that monitoring attributes the
// operation to the key that actually signed, not to the primary key.
func TestPrehashSignerMonitoringLogsSigningKey(t *testing.T) {
	defer internalregistry.ClearMonitoringClient()
	client := fakemonitoring.NewClient("fake-client")
	if err := internalregistry.RegisterMonitoringClient(client); err != nil {
		t.Fatalf("internalregistry.RegisterMonitoringClient() err = %v, want nil", err)
	}

	privHandleAfterRotation, pubHandleBeforeRotation, oldID, newID := rotationSetup(t)
	// Tink only emits monitoring events for keysets carrying annotations, and
	// only the signing keyset gets them here, so the signing event is the only
	// one expected below.
	manager := keyset.NewManagerFromHandle(privHandleAfterRotation)
	if err := manager.SetAnnotations(map[string]string{"foo": "bar"}); err != nil {
		t.Fatalf("manager.SetAnnotations() err = %v, want nil", err)
	}
	annotatedPrivHandle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	prehasher, err := signprehash.NewPrehash(pubHandleBeforeRotation)
	if err != nil {
		t.Fatalf("signprehash.NewPrehash() err = %v, want nil", err)
	}
	signer, err := signprehash.NewPrehashSigner(annotatedPrivHandle)
	if err != nil {
		t.Fatalf("signprehash.NewPrehashSigner() err = %v, want nil", err)
	}

	prehash, err := prehasher.ComputePrehash([]byte("message signed by the non-primary key"))
	if err != nil {
		t.Fatalf("prehasher.ComputePrehash() err = %v, want nil", err)
	}
	if _, err := signer.SignPrehash(prehash); err != nil {
		t.Fatalf("signer.SignPrehash() err = %v, want nil", err)
	}

	gotEvents := client.Events()
	if len(gotEvents) != 1 {
		t.Fatalf("len(gotEvents) = %d, want 1", len(gotEvents))
	}
	if gotEvents[0].KeyID != oldID {
		t.Errorf("gotEvents[0].KeyID = %d, want %d (the signing key, not primary %d)", gotEvents[0].KeyID, oldID, newID)
	}
}
