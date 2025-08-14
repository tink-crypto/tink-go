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
	"fmt"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveregistry"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

const (
	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
	p256PrivateKeyHex      = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	p256PublicKeyPointXHex = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	p256PublicKeyPointYHex = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	p256PublicKeyPointHex  = "04" + p256PublicKeyPointXHex + p256PublicKeyPointYHex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
	p384PrivateKeyHex      = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5"
	p384PublicKeyPointXHex = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13"
	p384PublicKeyPointYHex = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	p384PublicKeyPointHex  = "04" + p384PublicKeyPointXHex + p384PublicKeyPointYHex

	// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
	p521PrivateKeyHex      = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	p521PublicKeyPointXHex = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	p521PublicKeyPointYHex = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	p521PublicKeyPointHex  = "04" + p521PublicKeyPointXHex + p521PublicKeyPointYHex
)

func mustCreateParameters(t *testing.T, kidStrategy jwtecdsa.KIDStrategy, alg jwtecdsa.Algorithm) *jwtecdsa.Parameters {
	t.Helper()
	params, err := jwtecdsa.NewParameters(kidStrategy, alg)
	if err != nil {
		t.Fatalf("jwtecdsa.NewParameters() err = %v, want nil", err)
	}
	return params
}

func mustCreateJWTECDSAPublicKey(t *testing.T, opts jwtecdsa.PublicKeyOpts) *jwtecdsa.PublicKey {
	t.Helper()
	key, err := jwtecdsa.NewPublicKey(opts)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPublicKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateJWTECDSAPrivateKey(t *testing.T, keyBytes []byte, pub *jwtecdsa.PublicKey) *jwtecdsa.PrivateKey {
	t.Helper()
	secretDataKeyValue := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
	key, err := jwtecdsa.NewPrivateKeyFromPublicKey(secretDataKeyValue, pub)
	if err != nil {
		t.Fatalf("jwtecdsa.NewPrivateKeyFromPublicKey() err = %v, want nil", err)
	}
	return key
}

func TestJWTECDSASignerVerfierCreator(t *testing.T) {
	for _, tc := range []struct {
		name       string
		algorithm  jwtecdsa.Algorithm
		privKeyHex string
		pubKeyHex  string
	}{
		{"ES256", jwtecdsa.ES256, p256PrivateKeyHex, p256PublicKeyPointHex},
		{"ES384", jwtecdsa.ES384, p384PrivateKeyHex, p384PublicKeyPointHex},
		{"ES512", jwtecdsa.ES512, p521PrivateKeyHex, p521PublicKeyPointHex},
	} {
		for _, strategyAndKID := range []struct {
			strategy jwtecdsa.KIDStrategy
			kid      string
			hasKID   bool
		}{
			{jwtecdsa.Base64EncodedKeyIDAsKID, "", false},
			{jwtecdsa.CustomKID, "custom-kid", true},
			{jwtecdsa.IgnoredKID, "", false},
		} {
			t.Run(fmt.Sprintf("%s_%s", tc.name, strategyAndKID.strategy), func(t *testing.T) {
				params := mustCreateParameters(t, strategyAndKID.strategy, tc.algorithm)
				pubKeyOpts := jwtecdsa.PublicKeyOpts{
					Parameters:  params,
					PublicPoint: mustHexDecode(t, tc.pubKeyHex),
				}
				if strategyAndKID.strategy == jwtecdsa.Base64EncodedKeyIDAsKID {
					pubKeyOpts.IDRequirement = 0x01020304
					pubKeyOpts.HasCustomKID = false
				} else if strategyAndKID.strategy == jwtecdsa.CustomKID {
					pubKeyOpts.HasCustomKID = true
					pubKeyOpts.CustomKID = strategyAndKID.kid
				}
				pubKey := mustCreateJWTECDSAPublicKey(t, pubKeyOpts)
				privKey := mustCreateJWTECDSAPrivateKey(t, mustHexDecode(t, tc.privKeyHex), pubKey)

				p, err := primitiveregistry.Primitive(privKey)
				if err != nil {
					t.Fatalf("primitiveregistry.Primitive() err = %v, want nil", err)
				}
				signer, ok := p.(jwt.Signer)
				if !ok {
					t.Fatalf("primitiveregistry.Primitive(%T) = %T, want sKID", privKey, p)
				}

				// Create a public keyset handle.
				km := keyset.NewManager()

				keyID, err := km.AddKeyWithOpts(pubKey, internalapi.Token{}, keyset.WithFixedID(0x01020304))
				if err != nil {
					t.Fatalf("km.AddKey() err = %v, want nil", err)
				}
				if err := km.SetPrimary(keyID); err != nil {
					t.Fatalf("km.SetPrimary() err = %v, want nil", err)
				}
				pubKeyHandle, err := km.Handle()
				if err != nil {
					t.Fatalf("km.Handle() err = %v, want nil", err)
				}

				verifier, err := jwt.NewVerifier(pubKeyHandle)
				if err != nil {
					t.Fatalf("jwt.NewVerifier() err = %v, want nil", err)
				}

				// Try to sign and verify a JWT with the issuer set.
				issuer := "https://www.example.com"
				rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
					Issuer:            &issuer,
					WithoutExpiration: true,
				})
				if err != nil {
					t.Fatalf("jwt.NewRawJWT() err = %v, want nil", err)
				}
				signedToken, err := signer.SignAndEncode(rawJWT)
				if err != nil {
					t.Fatalf("signer.SignAndEncode() err = %v, want nil", err)
				}
				validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
					ExpectedIssuer:         &issuer,
					AllowMissingExpiration: true,
				})
				if err != nil {
					t.Fatalf("jwt.NewValidator() err = %v, want nil", err)
				}
				verifiedJWT, err := verifier.VerifyAndDecode(signedToken, validator)
				if err != nil {
					t.Fatalf("verifier.VerifyAndDecode() err = %v, want nil", err)
				}
				gotIssuer, err := verifiedJWT.Issuer()
				if err != nil {
					t.Fatalf("verifiedJWT.Issuer() err = %v, want nil", err)
				}
				if gotIssuer != issuer {
					t.Errorf("verifiedJWT.Issuer() = %q, want %q", gotIssuer, issuer)
				}
			})
		}
	}
}
