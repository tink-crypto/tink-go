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

package jwtsignatureconfig_test

import (
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config/jwtsignatureconfig"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestConfigV0JWTSignatureFailsIfKeyNotSignature(t *testing.T) {
	configV0 := jwtsignatureconfig.V0()
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

func mustBase64Decode(t *testing.T, in string) []byte {
	t.Helper()
	d, err := base64.RawURLEncoding.DecodeString(in)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %v", in, err)
	}
	return d
}

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	n2048Base64    = "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ"
	d2048Base64    = "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkOESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1GcGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q"
	p2048Base64    = "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs"
	q2048Base64    = "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc"
	dp2048Base64   = "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-YBN362A_1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU"
	dq2048Base64   = "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1BwmHasWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8"
	qInv2048Base64 = "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9zuEh_EtEecI35yjPYzq2CowOzQT85-O6pVk"
)

func TestConfigV0WithJWTSignatureKey(t *testing.T) {
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
	}

	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	jwtECDSAParams, err := jwtecdsa.NewParameters(jwtecdsa.IgnoredKID, jwtecdsa.ES256)
	if err != nil {
		t.Fatalf("jwtecdsa.NewParameters() err = %v, want nil", err)
	}
	jwtECDSAPublicKey, err := jwtecdsa.NewPublicKey(jwtecdsa.PublicKeyOpts{
		Parameters:    jwtECDSAParams,
		PublicPoint:   slices.Concat([]byte{4}, mustBase64Decode(t, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), mustBase64Decode(t, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
		IDRequirement: 0,
	})
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	secretDataKeyValue := secretdata.NewBytesFromData(mustBase64Decode(t, "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"), insecuresecretdataaccess.Token{})
	jwtECDSAPrivateKey, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, jwtECDSAPublicKey)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	ecdsaJWT := "eyJhbGciOiJFUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"

	jwtRSASSAPKCS1Params, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	jwtRSASSAPKCS1PublicKey, err := jwtrsassapkcs1.NewPublicKey(jwtrsassapkcs1.PublicKeyOpts{
		Parameters:    jwtRSASSAPKCS1Params,
		IDRequirement: 0,
		Modulus:       mustBase64Decode(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	jwtRSASSAPKCS1PrivateKey, err := jwtrsassapkcs1.NewPrivateKey(jwtrsassapkcs1.PrivateKeyOpts{
		PublicKey: jwtRSASSAPKCS1PublicKey,
		D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPrivateKey() err = %v, want nil", err)
	}
	rsaSSAPKCS1JWT := "eyJhbGciOiJSUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"F_h14Jj1TXhtO6DzWk5Ecei4h7I-" +
		"y9aCLUn8wMzFaIQ76MbE5qjkvLGyVpf5zwhrEx8WGmQTjufQ1kIFiu45O9qg0ZnDvRunMi" +
		"73F80PxXOdbWIUfY1QF1JCO-TqFHfymG8xShpQEm6R-WeF-" +
		"LeWxa6GWaNrJcvM4aggotdGKhgHC7SwYXVYjPhmH4r8jaUuGzCIO_iQb31n-" +
		"aR05XR16xti54pIgWlxXNgLhZ13umDeohZ6xkSny4HFvsJ2j08zo1CXtGOPdd34IKv4Y5S" +
		"xKJ5YwXVLukyGqvPLy8PNCkQlh32N5kjh9IGdg25OgR08ADQjRKinVjO_UxROv0bj4Q"

	jwtRSASSAPSSParams, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v, want nil", err)
	}
	jwtRSASSAPSSPublicKey, err := jwtrsassapss.NewPublicKey(jwtrsassapss.PublicKeyOpts{
		Parameters:    jwtRSASSAPSSParams,
		IDRequirement: 0,
		Modulus:       mustBase64Decode(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPublicKey() err = %v, want nil", err)
	}
	jwtRSASSAPSSPrivateKey, err := jwtrsassapss.NewPrivateKey(jwtrsassapss.PrivateKeyOpts{
		PublicKey: jwtRSASSAPSSPublicKey,
		D:         secretdata.NewBytesFromData(mustBase64Decode(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Decode(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Decode(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	rsaSSAPSSJWT := "eyJhbGciOiJQUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"WeMZxYgxDNYFbVm2-pt3uxlj1fIS540KIz1mUMwBfcWunpduvtzj_fWPJv_" +
		"bqRC78GdqUaOju01Sega8ECcVsg_8guRyJOl_" +
		"BmE9c6kxzSiPyZJ9f1xUjx9WfQ5kcoYMNMVJ_" +
		"gUO9QbWin23UiHBBs61rolzn0M6xfNS6MkaYXfsa8aYOWAmsLU_" +
		"6WOQtN645bSyoyHDIah2dHXZXQBc6SkqLP8fW1oiTLU4PcVr6SzQIHfK0kS674lqqmdFVK" +
		"QfyIakLEhGsQuZ0XzKRE-RbUrQGelKiC1q5Jz3Gq0nAGqOSPkFMA_" +
		"5TK1TQhykfbIuXYAClbt1tM74ee27sb2uuQ"

	for _, tc := range []struct {
		name       string
		jwt        string
		privateKey key.Key
		publicKey  key.Key
	}{
		{
			name:       "jwtecdsa",
			publicKey:  jwtECDSAPublicKey,
			privateKey: jwtECDSAPrivateKey,
			jwt:        ecdsaJWT,
		},
		{
			name:       "jwtrsassapkcs1",
			publicKey:  jwtRSASSAPKCS1PublicKey,
			privateKey: jwtRSASSAPKCS1PrivateKey,
			jwt:        rsaSSAPKCS1JWT,
		},
		{
			name:       "jwtrsassapss",
			publicKey:  jwtRSASSAPSSPublicKey,
			privateKey: jwtRSASSAPSSPrivateKey,
			jwt:        rsaSSAPSSJWT,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configV0 := jwtsignatureconfig.V0()
			p1, err := configV0.PrimitiveFromKey(tc.publicKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			verifier, ok := p1.(jwt.Verifier)
			if !ok {
				t.Fatalf("primitive is of type %T, want jwt.Verifier", p1)
			}
			p2, err := configV0.PrimitiveFromKey(tc.privateKey, internalapi.Token{})
			if err != nil {
				t.Fatalf("configV0.PrimitiveFromKey() err = %v, want nil", err)
			}
			signer, ok := p2.(jwt.Signer)
			if !ok {
				t.Fatalf("primitive is of type %T, want jwt.Signer", p2)
			}

			// Verify the JWTs test vector.
			if _, err := verifier.VerifyAndDecode(tc.jwt, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() err = %v, want nil", err)
			}

			// Sign and verify
			iss := "issuer"
			rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
				Issuer:            &iss,
				WithoutExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewRawJWT() = %v, want nil", err)
			}
			signedJWT, err := signer.SignAndEncode(rawJWT)
			if err != nil {
				t.Fatalf("signer.SignAndEncode() = %v, want nil", err)
			}
			validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
				ExpectedIssuer:         &iss,
				AllowMissingExpiration: true,
			})
			if err != nil {
				t.Fatalf("NewValidator() = %v, want nil", err)
			}
			if _, err := verifier.VerifyAndDecode(signedJWT, validator); err != nil {
				t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
			}
		})
	}
}
