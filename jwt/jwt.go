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

// Package jwt implements a subset of JSON Web Token (JWT) as defined by RFC 7519 (https://tools.ietf.org/html/rfc7519) that is considered safe and most often used.
package jwt

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/core/registry"

	_ "github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa" // Register jwtecdsa keys and proto serialization.
)

// A generic error returned when something went wrong before validation
var errJwtVerification = errors.New("verification failed")
var errJwtExpired = errors.New("token has expired")

// IsExpirationErr returns true if err was returned by a JWT verification for a token
// with a valid signature that is expired.
//
// Note that if the corresponding verification key has been removed from the keyset,
// verification will not return an expiration error even if the token is expired, because
// the expiration is only verified if the signature is valid.
func IsExpirationErr(err error) bool {
	return err == errJwtExpired
}

func init() {
	if err := registry.RegisterKeyManager(new(jwtHMACKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT HMAC key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtECDSAVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT ECDSA verifier key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtECDSASignerKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT ECDSA signer key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtRSSignerKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT RSA SSA PKCS1 signer key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtRSVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT RSA SSA PKCS1 verifier key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtPSSignerKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT RSA SSA PSS signer key manager: %v", err))
	}
	if err := registry.RegisterKeyManager(new(jwtPSVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("jwt.init() failed registering JWT RSA SSA PSS verifier key manager: %v", err))
	}
	// NOTE: We can register primitive constructors here only after all keys are
	// defined and have a primitive constructor.
}
