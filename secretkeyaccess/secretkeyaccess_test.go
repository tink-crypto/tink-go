// Copyright 2024 Google LLC
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

package secretkeyaccess_test

import (
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretkeyaccess"
	"github.com/tink-crypto/tink-go/v2/secretkeyaccess"
)

func TestValidateWithValidToken(t *testing.T) {
	if err := secretkeyaccess.Validate(insecuresecretkeyaccess.Token{}); err != nil {
		t.Errorf("secretkeyaccess.Validate(insecuresecretkeyaccess.Token{}) = %v, want nil", err)
	}
}

func TestValidateWithInvalidTokenReturnsError(t *testing.T) {
	if err := secretkeyaccess.Validate(nil); err == nil {
		t.Errorf("secretkeyaccess.Validate(nil) = nil, want error")
	}
	if err := secretkeyaccess.Validate(42); err == nil {
		t.Errorf("secretkeyaccess.Validate(42) = nil, want error")
	}
	if err := secretkeyaccess.Validate("token"); err == nil {
		t.Errorf("secretkeyaccess.Validate(\"token\") = nil, want error")
	}
	if err := secretkeyaccess.Validate(&insecuresecretkeyaccess.Token{}); err == nil {
		t.Errorf("secretkeyaccess.Validate(&insecuresecretkeyaccess.Token{}) = nil, want error")
	}
}
