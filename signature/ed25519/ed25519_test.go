// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ed25519_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature/ed25519"
	"github.com/tink-crypto/tink-go/v2/signature"
)

func TestCreateKeysetHandleFromParameters(t *testing.T) {
	params, err := ed25519.NewParameters(ed25519.VariantNoPrefix)
	if err != nil {
		t.Fatalf("ed25519.NewParameters(ed25519.VariantNoPrefix) err = %v, want nil", err)
	}

	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(&params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	manager.SetPrimary(keyID)
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}

	// Make sure that we can sign and verify with the generated key.
	signer, err := signature.NewSigner(handle)
	if err != nil {
		t.Fatalf("signature.NewSigner(handle) err = %v, want nil", err)
	}
	message := []byte("message")
	signatureBytes, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("signer.Sign(%v) err = %v, want nil", message, err)
	}
	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	verifier, err := signature.NewVerifier(publicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(handle) err = %v, want nil", err)
	}
	if err := verifier.Verify(signatureBytes, message); err != nil {
		t.Fatalf("verifier.Verify(%v, %v) err = %v, want nil", signatureBytes, message, err)
	}

	// Create another keyset handle from the same parameters.
	anotherManager := keyset.NewManager()
	keyID, err = anotherManager.AddNewKeyFromParameters(&params)
	if err != nil {
		t.Fatalf("anotherManager.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	anotherManager.SetPrimary(keyID)
	anotherHandle, err := anotherManager.Handle()
	if err != nil {
		t.Fatalf("anotherManager.Handle() err = %v, want nil", err)
	}
	anotherPublicHandle, err := anotherHandle.Public()
	if err != nil {
		t.Fatalf("anotherHandle.Public() err = %v, want nil", err)
	}

	// Get the primary key entry from both keyset handles.
	entry, err := handle.Primary()
	if err != nil {
		t.Fatalf("handle.Primary() err = %v, want nil", err)
	}
	anotherEntry, err := anotherHandle.Primary()
	if err != nil {
		t.Fatalf("anotherHandle.Primary() err = %v, want nil", err)
	}

	// Make sure that keys are different.
	if entry.KeyID() == anotherEntry.KeyID() {
		t.Fatalf("entry.KeyID() = %v, want different from anotherEntry.KeyID() = %v", entry.KeyID(), anotherEntry.KeyID())
	}
	if entry.Key().Equal(anotherEntry.Key()) {
		t.Fatalf("entry.Key().Equal(anotherEntry.Key()) = true, want false")
	}
	publicEntry, err := publicHandle.Primary()
	if err != nil {
		t.Fatalf("handle.Primary() err = %v, want nil", err)
	}
	anotherPublicEntry, err := anotherHandle.Primary()
	if err != nil {
		t.Fatalf("anotherHandle.Primary() err = %v, want nil", err)
	}
	if publicEntry.KeyID() == anotherPublicEntry.KeyID() {
		t.Fatalf("publicEntry.KeyID() = %v, want different from anotherPublicEntry.KeyID() = %v", publicEntry.KeyID(), anotherPublicEntry.KeyID())
	}
	if publicEntry.Key().Equal(anotherPublicEntry.Key()) {
		t.Fatalf("publicEntry.Key().Equal(anotherPublicEntry.Key()) = true, want false")
	}

	// Make sure that a different generated key cannot verify the signature.
	anotherVerifier, err := signature.NewVerifier(anotherPublicHandle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(anotherHandle) err = %v, want nil", err)
	}
	if err := anotherVerifier.Verify(signatureBytes, message); err == nil {
		t.Fatalf("anotherVerifier.Verify(%v, %v) err = nil, want error", signatureBytes, message)
	}
}
