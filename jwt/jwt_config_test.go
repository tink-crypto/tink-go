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
	"slices"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/config"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwthmac"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapss"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

func TestRegisterJWTHMACPrimitiveConstructor(t *testing.T) {
	// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.
	keyBytes := mustBase64Dec(t, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	params := mustCreateJWTHMACParameters(t, len(keyBytes), jwthmac.IgnoredKID, jwthmac.HS256)
	jwtHMACKey := mustCreateJWTHMACKey(t, jwthmac.KeyOpts{
		Parameters:    params,
		KeyBytes:      secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{}),
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

func TestRegisterJWTECDSAPrimitiveConstructor(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
	params, err := jwtecdsa.NewParameters(jwtecdsa.IgnoredKID, jwtecdsa.ES256)
	if err != nil {
		t.Fatalf("jwtecdsa.NewParameters() err = %v, want nil", err)
	}
	publicKey, err := jwtecdsa.NewPublicKey(jwtecdsa.PublicKeyOpts{
		Parameters:    params,
		PublicPoint:   slices.Concat([]byte{4}, mustBase64Dec(t, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), mustBase64Dec(t, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
		IDRequirement: 0,
	})
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	secretDataKeyValue := secretdata.NewBytesFromData(mustBase64Dec(t, "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"), insecuresecretdataaccess.Token{})
	privateKey, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, publicKey)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}

	token := "eyJhbGciOiJFUzI1NiJ9" +
		"." +
		// {"iss":"joe",
		//  "exp":1300819380,
		//  "http://example.com/is_root":true}
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"

	b := config.NewBuilder()
	configWithoutJWTHMAC := b.Build()

	// Should fail because jwt.RegisterJWTECDSAPrimitiveConstructor() was not called.
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(publicKey) err = nil, want error")
	}
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(privateKey) err = nil, want error")
	}

	// Register jwt.RegisterJWTECDSAPrimitiveConstructor() and check that it now works.
	if err := jwt.RegisterJWTECDSAPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("jwt.RegisterJWTECDSAPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithJWTHMAC := b.Build()
	p1, err := configWithJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	signer, ok := p1.(jwt.Signer)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p1))
	}
	p2, err := configWithJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	verifier, ok := p2.(jwt.Verifier)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p2))
	}
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// Sign and verify
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
	validator2, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:         &iss,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatalf("NewValidator() = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(signedJWT, validator2); err != nil {
		t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
	}
}

const (
	// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
	d2048Base64 = "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkOESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1GcGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q"
	p2048Base64 = "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs"
	q2048Base64 = "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZz3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc"
)

func TestRegisterJWTRSASSAPKCS1PrimitiveConstructor(t *testing.T) {
	params, err := jwtrsassapkcs1.NewParameters(jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapkcs1.RS256,
		KidStrategy:       jwtrsassapkcs1.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewParameters() err = %v, want nil", err)
	}
	publicKey, err := jwtrsassapkcs1.NewPublicKey(jwtrsassapkcs1.PublicKeyOpts{
		Parameters:    params,
		IDRequirement: 0,
		Modulus:       mustBase64Dec(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPublicKey() err = %v, want nil", err)
	}
	privateKey, err := jwtrsassapkcs1.NewPrivateKey(jwtrsassapkcs1.PrivateKeyOpts{
		PublicKey: publicKey,
		D:         secretdata.NewBytesFromData(mustBase64Dec(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Dec(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Dec(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapkcs1.NewPrivateKey() err = %v, want nil", err)
	}
	token := "eyJhbGciOiJSUzI1NiJ9" +
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

	b := config.NewBuilder()
	configWithoutJWTHMAC := b.Build()

	// Should fail because jwt.RegisterJWTRSASSAPKCS1PrimitiveConstructor() was not called.
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(publicKey) err = nil, want error")
	}
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(privateKey) err = nil, want error")
	}

	// Register jwt.RegisterJWTRSASSAPKCS1PrimitiveConstructor() and check that it now works.
	if err := jwt.RegisterJWTRSASSAPKCS1PrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("jwt.RegisterJWTRSASSAPKCS1PrimitiveConstructor() err = %v, want nil", err)
	}
	configWithJWTHMAC := b.Build()
	p1, err := configWithJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	signer, ok := p1.(jwt.Signer)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p1))
	}
	p2, err := configWithJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	verifier, ok := p2.(jwt.Verifier)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p2))
	}
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// Sign and verify
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
	validator2, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:         &iss,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatalf("NewValidator() = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(signedJWT, validator2); err != nil {
		t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
	}
}

func TestRegisterJWTRSASSAPSSPrimitiveConstructor(t *testing.T) {
	params, err := jwtrsassapss.NewParameters(jwtrsassapss.ParametersOpts{
		ModulusSizeInBits: 2048,
		PublicExponent:    0x10001,
		Algorithm:         jwtrsassapss.PS256,
		KidStrategy:       jwtrsassapss.IgnoredKID,
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewParameters() err = %v, want nil", err)
	}
	publicKey, err := jwtrsassapss.NewPublicKey(jwtrsassapss.PublicKeyOpts{
		Parameters:    params,
		IDRequirement: 0,
		Modulus:       mustBase64Dec(t, n2048Base64),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPublicKey() err = %v, want nil", err)
	}
	privateKey, err := jwtrsassapss.NewPrivateKey(jwtrsassapss.PrivateKeyOpts{
		PublicKey: publicKey,
		D:         secretdata.NewBytesFromData(mustBase64Dec(t, d2048Base64), insecuresecretdataaccess.Token{}),
		P:         secretdata.NewBytesFromData(mustBase64Dec(t, p2048Base64), insecuresecretdataaccess.Token{}),
		Q:         secretdata.NewBytesFromData(mustBase64Dec(t, q2048Base64), insecuresecretdataaccess.Token{}),
	})
	if err != nil {
		t.Fatalf("jwtrsassapss.NewPrivateKey() err = %v, want nil", err)
	}
	token := "eyJhbGciOiJQUzI1NiJ9" +
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

	b := config.NewBuilder()
	configWithoutJWTHMAC := b.Build()

	// Should fail because jwt.RegisterJWTRSASSAPSSPrimitiveConstructor() was not called.
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(publicKey) err = nil, want error")
	}
	if _, err := configWithoutJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{}); err == nil {
		t.Fatalf("configWithoutJWTHMAC.PrimitiveFromKey(privateKey) err = nil, want error")
	}

	// Register jwt.RegisterJWTRSASSAPSSPrimitiveConstructor() and check that it now works.
	if err := jwt.RegisterJWTRSASSAPSSPrimitiveConstructor(b, internalapi.Token{}); err != nil {
		t.Fatalf("jwt.RegisterJWTRSASSAPSSPrimitiveConstructor() err = %v, want nil", err)
	}
	configWithJWTHMAC := b.Build()
	p1, err := configWithJWTHMAC.PrimitiveFromKey(privateKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	signer, ok := p1.(jwt.Signer)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p1))
	}
	p2, err := configWithJWTHMAC.PrimitiveFromKey(publicKey, internalapi.Token{})
	if err != nil {
		t.Fatalf(" configWithJWTHMAC.PrimitiveFromKey() err = %v, want nil", err)
	}
	verifier, ok := p2.(jwt.Verifier)
	if !ok {
		t.Fatalf("p was of type %v, want jwt.Signer", reflect.TypeOf(p2))
	}
	iss := "joe"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer: &iss,
		FixedNow:       time.Unix(1300819380, 0).Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewValidator() err = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(token, validator); err != nil {
		t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
	}

	// Sign and verify
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
	validator2, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:         &iss,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatalf("NewValidator() = %v, want nil", err)
	}
	if _, err := verifier.VerifyAndDecode(signedJWT, validator2); err != nil {
		t.Errorf("verifier.VerifyAndDecode() = %v, want nil", err)
	}
}
