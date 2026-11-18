// Copyright 2022 Google LLC
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

package testkeyset_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/internal/keytest"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
)

func mustCreateTestKeysetHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	km := keyset.NewManager()
	p, err := keytest.NewParameters(keytest.VariantTink)
	if err != nil {
		t.Fatalf("keytest.NewParameters(keytest.VariantTink) err = %v, want nil", err)
	}
	keyID, err := km.AddNewKeyFromParameters(p)
	if err != nil {
		t.Fatalf("km.AddNewKeyFromParameters(%v) err = %v, want nil", p, err)
	}
	if err := km.SetPrimary(keyID); err != nil {
		t.Fatalf("km.SetPrimary(%d) err = %v, want nil", keyID, err)
	}
	handle, err := km.Handle()
	if err != nil {
		t.Fatalf("km.Handle() err = %v, want nil", err)
	}
	return handle
}

func TestNewHandleCallsAreConsistent(t *testing.T) {
	ks := insecurecleartextkeyset.KeysetMaterial(mustCreateTestKeysetHandle(t))
	handle1, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle() err = %v, want nil", err)
	}
	handle2 := testkeyset.KeysetHandle(ks)
	if handle2 == nil {
		t.Fatal("testkeyset.KeysetHandle() = nil, want non-nil")
	}
	if !handle1.Equal(handle2) {
		t.Error("testkeyset.NewHandle(ks).Equal(testkeyset.KeysetHandle(ks)) = false, want true")
	}
}
