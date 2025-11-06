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

package jwtmacconfig_test

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/jwtmacconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestConfigV0JWTMACFailsIfKeyNotMAC(t *testing.T) {
	configV0 := jwtmacconfig.V0()
	aesGCMParams, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		KeySizeInBytes: 32,
		TagSizeInBytes: 16,
		Variant:        aesgcm.VariantNoPrefix,
		IVSizeInBytes:  12,
	})
	if err != nil {
		t.Fatalf("aessiv.NewParameters() err = %v, want nil", err)
	}
	aesGCMKey, err := aesgcm.NewKey(secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{}), 0, aesGCMParams)
	if err != nil {
		t.Fatalf(" aessiv.NewKey() err = %v, want nil", err)
	}
	if _, err := configV0.PrimitiveFromKey(aesGCMKey, internalapi.Token{}); err == nil {
		t.Errorf("configV0.PrimitiveFromKeyData() err = nil, want error")
	}
}

func mustBase64Dec(t *testing.T, s string) []byte {
	t.Helper()
	res, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(%q) err = %v, want nil", s, err)
	}
	return res
}

func TestConfigV0WithJWTHMACKey(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.
	token := "eyJhbGciOiJIUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"dCfJaSBBMSnC8CXslIf5orCzS7AboBan4qE7aXuYSDs"
	keyBytes := mustBase64Dec(t, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	configV0 := jwtmacconfig.V0()
	params, err := jwthmac.NewParameters(len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS256)
	if err != nil {
		t.Fatalf("jwthmac.NewParameters() err = %v, want nil", err)
	}
	key, err := jwthmac.NewKey(jwthmac.KeyOpts{
		Parameters: params,
		KeyBytes:   secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwthmac.NewKey() err = %v, want nil", err)
	}
	p, err := configV0.PrimitiveFromKey(key, internalapi.Token{})
	if err != nil {
		t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
	}
	m, ok := p.(jwt.MAC)
	if !ok {
		t.Fatalf("primitive is of type %v, want jwt.MAC", reflect.TypeOf(p))
	}
	// Verify the test vector
	if _, err := m.VerifyMACAndDecode(token, validator); err != nil {
		t.Errorf("m.VerifyMACAndDecode() err = %v, want nil", err)
	}

	// Sign and verify
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
		Issuer:            &iss,
		WithoutExpiration: true,
	})
	if err != nil {
		t.Fatalf("jwt.NewRawJWT() = %v, want nil", err)
	}
	gotJWT, err := m.ComputeMACAndEncode(rawJWT)
	if err != nil {
		t.Fatalf("m.ComputeMACAndEncode() = %v, want nil", err)
	}
	validator2, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:         &iss,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatalf("jwt.NewValidator() = %v, want nil", err)
	}
	if _, err := m.VerifyMACAndDecode(gotJWT, validator2); err != nil {
		t.Errorf("m.VerifyMACAndDecode() = %v, want nil", err)
	}
}
