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
	"encoding/base64"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func mustCreateJWTHMACParameters(t *testing.T, keySize int, kidStrategy jwthmac.KIDStrategy, algorithm jwthmac.Algorithm) *jwthmac.Parameters {
	t.Helper()
	params, err := jwthmac.NewParameters(keySize, kidStrategy, algorithm)
	if err != nil {
		t.Fatalf("jwthmac.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateJWTHMACKey(t *testing.T, opts jwthmac.KeyOpts) *jwthmac.Key {
	t.Helper()
	key, err := jwthmac.NewKey(opts)
	if err != nil {
		t.Fatalf("jwthmac.NewKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateKeysetHandle(t *testing.T, k key.Key) *keyset.Handle {
	t.Helper()
	ksm := keyset.NewManager()
	if _, err := ksm.AddKeyWithOpts(k, internalapi.Token{}, keyset.AsPrimary()); err != nil {
		t.Fatalf("ksm.AddKey() err = %v, want nil", err)
	}
	keysetHandle, err := ksm.Handle()
	if err != nil {
		t.Fatalf("ksm.Handle() err = %v, want nil", err)
	}
	return keysetHandle
}

func TestJWTFullMACSignAndVerify(t *testing.T) {
	keyBytesHS256 := secretdata.NewBytesFromData([]byte("01234567890123456789012345678901"), insecuresecretdataaccess.Token{})
	keyBytesHS384 := secretdata.NewBytesFromData([]byte("012345678901234567890123456789012345678901234567"), insecuresecretdataaccess.Token{})
	keyBytesHS512 := secretdata.NewBytesFromData([]byte("0123456789012345678901234567890123456789012345678901234567890123"), insecuresecretdataaccess.Token{})

	for _, tc := range []struct {
		name    string
		key     key.Key
		otherOK []key.Key
	}{
		// HS256
		{
			name: "HS256_Base64EncodedKeyIDAsKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateJWTHMACParameters(t, 32, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS256),
				KeyBytes:      keyBytesHS256,
				IDRequirement: 0x01020304,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 32, jwthmac.IgnoredKID, jwthmac.HS256),
					KeyBytes:   keyBytesHS256,
				}),
			},
		},
		{
			name: "HS256_CustomKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:   mustCreateJWTHMACParameters(t, 32, jwthmac.CustomKID, jwthmac.HS256),
				KeyBytes:     keyBytesHS256,
				CustomKID:    "custom-kid",
				HasCustomKID: true,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 32, jwthmac.IgnoredKID, jwthmac.HS256),
					KeyBytes:   keyBytesHS256,
				}),
			},
		},
		{
			name: "HS256_IgnoredKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters: mustCreateJWTHMACParameters(t, 32, jwthmac.IgnoredKID, jwthmac.HS256),
				KeyBytes:   keyBytesHS256,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters:   mustCreateJWTHMACParameters(t, 32, jwthmac.CustomKID, jwthmac.HS256),
					KeyBytes:     keyBytesHS256,
					CustomKID:    "custom-kid",
					HasCustomKID: true,
				}),
			},
		},
		// HS384
		{
			name: "HS384_Base64EncodedKeyIDAsKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateJWTHMACParameters(t, 48, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS384),
				KeyBytes:      keyBytesHS384,
				IDRequirement: 0x01020304,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 48, jwthmac.IgnoredKID, jwthmac.HS384),
					KeyBytes:   keyBytesHS384,
				}),
			},
		},
		{
			name: "HS384_CustomKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:   mustCreateJWTHMACParameters(t, 48, jwthmac.CustomKID, jwthmac.HS384),
				KeyBytes:     keyBytesHS384,
				CustomKID:    "custom-kid",
				HasCustomKID: true,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 48, jwthmac.IgnoredKID, jwthmac.HS384),
					KeyBytes:   keyBytesHS384,
				}),
			},
		},
		{
			name: "HS384_IgnoredKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters: mustCreateJWTHMACParameters(t, 48, jwthmac.IgnoredKID, jwthmac.HS384),
				KeyBytes:   keyBytesHS384,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters:   mustCreateJWTHMACParameters(t, 48, jwthmac.CustomKID, jwthmac.HS384),
					KeyBytes:     keyBytesHS384,
					CustomKID:    "custom-kid",
					HasCustomKID: true,
				}),
			},
		},
		// HS512
		{
			name: "HS512_Base64EncodedKeyIDAsKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:    mustCreateJWTHMACParameters(t, 64, jwthmac.Base64EncodedKeyIDAsKID, jwthmac.HS512),
				KeyBytes:      keyBytesHS512,
				IDRequirement: 0x01020304,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 64, jwthmac.IgnoredKID, jwthmac.HS512),
					KeyBytes:   keyBytesHS512,
				}),
			},
		},
		{
			name: "HS512_CustomKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters:   mustCreateJWTHMACParameters(t, 64, jwthmac.CustomKID, jwthmac.HS512),
				KeyBytes:     keyBytesHS512,
				CustomKID:    "custom-kid",
				HasCustomKID: true,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters: mustCreateJWTHMACParameters(t, 64, jwthmac.IgnoredKID, jwthmac.HS512),
					KeyBytes:   keyBytesHS512,
				}),
			},
		},
		{
			name: "HS512_IgnoredKID",
			key: mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
				Parameters: mustCreateJWTHMACParameters(t, 64, jwthmac.IgnoredKID, jwthmac.HS512),
				KeyBytes:   keyBytesHS512,
			}),
			otherOK: []key.Key{
				mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
					Parameters:   mustCreateJWTHMACParameters(t, 64, jwthmac.CustomKID, jwthmac.HS512),
					KeyBytes:     keyBytesHS512,
					CustomKID:    "custom-kid",
					HasCustomKID: true,
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keysetHandle := mustCreateKeysetHandle(t, tc.key)
			mac, err := jwt.NewMAC(keysetHandle)
			if err != nil {
				t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
			}

			issuer := "https://www.example.com"
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
				Issuer:            &issuer,
				WithoutExpiration: true,
			})
			if err != nil {
				t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
			}
			compact, err := mac.ComputeMACAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("mac.ComputeMACAndEncode() err = %v, want nil", err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
				ExpectedIssuer:         &issuer,
				AllowMissingExpiration: true,
			})
			if err != nil {
				t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
			}
			verifiedJWT, err := mac.VerifyMACAndDecode(compact, validator)
			if err != nil {
				t.Fatalf("mac.VerifyMACAndDecode() err = %v, want nil", err)
			}
			gotIssuer, err := verifiedJWT.Issuer()
			if err != nil {
				t.Fatalf("verifiedJWT.Issuer() err = %v, want nil", err)
			}
			if gotIssuer != issuer {
				t.Errorf("verifiedJWT.Issuer() = %q, want %q", gotIssuer, issuer)
			}

			// Check other verifying keys.
			for _, otherKey := range tc.otherOK {
				keysetHandle := mustCreateKeysetHandle(t, otherKey)
				mac, err := jwt.NewMAC(keysetHandle)
				if err != nil {
					t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
				}
				if _, err := mac.VerifyMACAndDecode(compact, validator); err != nil {
					t.Errorf("mac.VerifyMACAndDecode() err = %v, want nil", err)
				}
			}
		})
	}
}

type jwtHMACTestVector struct {
	name      string
	k         key.Key
	jwt       string
	validator *jwt.Validator
}

func mustBase64Dec(t *testing.T, s string) []byte {
	t.Helper()
	res, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatalf("base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(%q) err = %v, want nil", s, err)
	}
	return res
}

// Similar to
// https://github.com/tink-crypto/tink-cc/blob/f2d9781905c160c342af96373d4b63b050652f68/tink/jwt/internal/jwt_mac_config_v0_test.cc#L150
func TestJWTFullMACTestVectors(t *testing.T) {
	var testVectors []jwtHMACTestVector
	// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.
	keyBytes := mustBase64Dec(t, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	// HS256
	{ // Ignored KID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS256)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "joe"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name: "HS256_IgnoredKID",
			k:    jwtHMACKey,
			jwt: "eyJhbGciOiJIUzI1NiJ9" +
				"." +
				// {"iss":"joe",
				//  "exp":1300819380,
				//  "http://example.com/is_root":true}
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"dCfJaSBBMSnC8CXslIf5orCzS7AboBan4qE7aXuYSDs",
			validator: validator,
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS256)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS256_Base64EncodedKeyIDAsKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"AQIDBA","alg":"HS256"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJIUzI1NiJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"LyeYhbBBMFNjdGo_Qz3SXB7QvYbb-i0Onswr5R7zKvg",
		})
	}
	{ // CustomKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.CustomKID, jwthmac.HS256)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
			CustomKID:     "custom-kid",
			HasCustomKID:  true,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS256_CustomKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"custom-kid","alg":"HS256"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiSFMyNTYifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"9t5toIv2qTXGyaKYPKZO_b40dtVWIYj8sPLXzFhNXk0",
		})
	}
	// HS384
	{ // Ignored KID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS384)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "joe"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name: "HS384_IgnoredKID",
			k:    jwtHMACKey,
			jwt: "eyJhbGciOiJIUzM4NCJ9" +
				"." +
				// {"iss":"joe",
				//  "exp":1300819380,
				//  "http://example.com/is_root":true}
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"oXDrZsBTd6_RlkXLUTQJ0DSfHx5raR4Pq5jlRHf5v0WTm-zt8xcsCvXagNl0J4eM",
			validator: validator,
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS384)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS384_Base64EncodedKeyIDAsKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"AQIDBA","alg":"HS384"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJIUzM4NCJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"0xtN9Qkt_cPWBmoeUBOv0j2a670zO_sdqfPdszBlwSrXqobs0ceTL7mLurMwi5C0",
		})
	}
	{ // CustomKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.CustomKID, jwthmac.HS384)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
			CustomKID:     "custom-kid",
			HasCustomKID:  true,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS384_CustomKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"custom-kid","alg":"HS384"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiSFMzODQifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"cd6Lfc4GKiM60UNT4uJtEKaus2BFOeSAS5sAsuddnFnM2xymi4R2ovKU9UVDdwNM",
		})
	}
	// HS512
	{ // Ignored KID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS512)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "joe"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer: &iss,
			FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name: "HS512_IgnoredKID",
			k:    jwtHMACKey,
			jwt: "eyJhbGciOiJIUzUxMiJ9" +
				"." +
				// {"iss":"joe",
				//  "exp":1300819380,
				//  "http://example.com/is_root":true}
				"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
				"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
				"." +
				"CyfHecbVPqPzB3zBwYd3rgVBi2Dgg-eAeX7JT8B85QbKLwSXyll8WKGdehse606szf9G3i-jr24QGkEtMAGSpg",
			validator: validator,
		})
	}
	{ // Base64EncodedKeyIDAsKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS512)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS512_Base64EncodedKeyIDAsKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"AQIDBA","alg":"HS512"}
			"eyJraWQiOiJBUUlEQkEiLCJhbGciOiJIUzUxMiJ9" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"lcfNNAdOQOICzBljppEt6VJnie9jrukliV2MjqLd2b4v_lpJVl0xP-rEqS53JMdqbqYUTcVpSxuSsyx4sQ744Q",
		})
	}
	{ // CustomKID
		params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.CustomKID, jwthmac.HS512)
		jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
			Parameters:    params,
			KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
			IDRequirement: 0,
			CustomKID:     "custom-kid",
			HasCustomKID:  true,
		})

		iss := "issuer"
		validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
			ExpectedIssuer:         &iss,
			AllowMissingExpiration: true,
		})
		if err != nil {
			t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
		}
		testVectors = append(testVectors, jwtHMACTestVector{
			name:      "HS512_CustomKID",
			k:         jwtHMACKey,
			validator: validator,
			jwt:
			// {"kid":"custom-kid","alg":"HS512"}
			"eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiSFM1MTIifQ" +
				"." +
				// {"iss":"issuer"}
				"eyJpc3MiOiJpc3N1ZXIifQ" +
				"." +
				"DPSsIDnvfudQYY7TZ5cznnnAXBKtYuLVZHyI-SHxaEcgOFLbysGhb8EWy_onqXVVDJeqnN_wzFXOojicY_dPsQ",
		})
	}
	for _, tc := range testVectors {
		t.Run(tc.name, func(t *testing.T) {
			keysetHandle := mustCreateKeysetHandle(t, tc.k)
			m, err := jwt.NewMAC(keysetHandle)
			if err != nil {
				t.Fatalf("jwt.NewMAC() err = %v, want nil", err)
			}
			// Verify the test vector
			if _, err := m.VerifyMACAndDecode(tc.jwt, tc.validator); err != nil {
				t.Fatalf("m.VerifyMACAndDecode() err = %v, want nil", err)
			}

			// Sign and verify
			iss := "issuer"
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
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
				ExpectedIssuer:         &iss,
				AllowMissingExpiration: true,
			})
			if err != nil {
				t.Fatalf("jwt.NewValidator() = %v, want nil", err)
			}
			if _, err := m.VerifyMACAndDecode(gotJWT, validator); err != nil {
				t.Errorf("m.VerifyMACAndDecode() = %v, want nil", err)
			}
		})
	}
}
