// Copyright 2025 Google LLC
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

package testutil_test

import (
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead/internal/testutil"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	tinktestutil "github.com/tink-crypto/tink-go/v2/testutil"
)

func TestEncryptDecryptFailsWithFailingAEAD(t *testing.T) {
	failingAEAD := tinktestutil.NewAlwaysFailingAead(fmt.Errorf("test error"))
	a, err := subtle.NewAESGCM(random.GetRandomBytes(32))
	if err != nil {
		t.Fatalf("subtle.NewAESGCM() err = %v, want nil", err)
	}
	if err := testutil.EncryptDecrypt(failingAEAD, a); err == nil {
		t.Errorf("EncryptDecrypt(failingAEAD, a) err = nil, want non-nil")
	}
	if err := testutil.EncryptDecrypt(a, failingAEAD); err == nil {
		t.Errorf("EncryptDecrypt(a, failingAEAD) err = nil, want non-nil")
	}
	if err := testutil.EncryptDecrypt(failingAEAD, failingAEAD); err == nil {
		t.Errorf("EncryptDecrypt(failingAEAD, failingAEAD) err = nil, want non-nil")
	}
}

func TestEncryptDecryptWorks(t *testing.T) {
	keyBytes := random.GetRandomBytes(32)
	encryptor, err := subtle.NewAESGCM(keyBytes)
	if err != nil {
		t.Fatalf("subtle.NewAESGCM() err = %v, want nil", err)
	}
	decryptor, err := subtle.NewAESGCM(keyBytes)
	if err != nil {
		t.Fatalf("subtle.NewAESGCM() err = %v, want nil", err)
	}
	if err := testutil.EncryptDecrypt(encryptor, decryptor); err != nil {
		t.Fatalf("subtle.NewAESGCM() err = %v, want nil", err)
	}
}
