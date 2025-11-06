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

package jwt_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil/testonlyinsecuresecretdataaccess"
)

func TestRegisterPrimitiveConstructor(t *testing.T) {
	// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.
	keyBytes := mustBase64Dec(t, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS256)
	jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
		Parameters:    params,
		KeyBytes:      secretdata.NewBytesFromData(keyBytes, testonlyinsecuresecretdataaccess.Token()),
		IDRequirement: 0,
	})
	token := "eyJhbGciOiJIUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"dCfJaSBBMSnC8CXslIf5orCzS7AboBan4qE7aXuYSDs"

	b := config.NewBuilder()
	configWithoutJWTHMAC := b.Build()

	// Should fail because jwt.RegisterJWTHMACPrimitiveConstructor() was not called.
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(jwtHMACKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey() err = nil, want error")
	}

	// Register jwt.RegisterJWTHMACPrimitiveConstructor() and check that it now works.
	if err := jwt.RegisterJWTHMACPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("jwt.RegisterJWTHMACPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithJWTHMAC := b.Build()
	primitive, err := configWithJWTHMAC.PrimitiveFromKey(jwtHMACKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	p, ok := primitive.(jwt.MAC)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.MAC", reflect.TypeOf(p))
	}
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := p.VerifyMACAndDecode(token, validator); err != nil {
		t.Fatalf("d.DecryptDeterministically() err = %v, want nil", err)
	}
}
