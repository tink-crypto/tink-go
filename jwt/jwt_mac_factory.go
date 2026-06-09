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

package jwt

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
)

type macAndKeyID struct {
	mac   MAC
	keyID uint32
}

// NewMAC generates a new [jwt.MAC] primitive with the global registry.
func NewMAC(handle *keyset.Handle) (MAC, error) {
	return NewMACWithConfig(handle, &registryconfig.RegistryConfig{})
}

// NewMACWithConfig generates a new [jwt.MAC] primitive with the provided
// [keyset.Config].
func NewMACWithConfig(handle *keyset.Handle, config keyset.Config) (MAC, error) {
	if handle.Len() == 0 {
		return nil, fmt.Errorf("jwt_mac_factory: empty or nil keyset handle")
	}
	var macs []macAndKeyID
	var primary macAndKeyID
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		p, isLegacyPrimitive, err := factoryutil.PrimitiveFromKey[MAC](entry.Key(), config)
		if err != nil {
			return nil, err
		}
		if isLegacyPrimitive {
			// Something is wrong, this should not happen.
			return nil, fmt.Errorf("jwt_mac_factory: full primitive is nil")
		}
		a := macAndKeyID{mac: p, keyID: entry.KeyID()}
		if entry.IsPrimary() {
			primary = a
		}
		macs = append(macs, a)
	}

	computeLogger, verifyLogger, err := createMacLoggers(handle)
	if err != nil {
		return nil, err
	}

	return &wrappedJWTMAC{
		macs:          macs,
		primary:       primary,
		computeLogger: computeLogger,
		verifyLogger:  verifyLogger,
	}, nil
}

// wrappedJWTMAC is a JWT MAC implementation that uses the underlying primitive
// set for JWT MAC.
type wrappedJWTMAC struct {
	macs          []macAndKeyID
	primary       macAndKeyID
	computeLogger monitoring.Logger
	verifyLogger  monitoring.Logger
}

var _ MAC = (*wrappedJWTMAC)(nil)

func createMacLoggers(kh *keyset.Handle) (monitoring.Logger, monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, nil, err
	}
	computeLogger, err := factory.CreateFor("jwtmac", "compute")
	if err != nil {
		return nil, nil, err
	}
	verifyLogger, err := factory.CreateFor("jwtmac", "verify")
	if err != nil {
		return nil, nil, err
	}
	return computeLogger, verifyLogger, nil
}

func (w *wrappedJWTMAC) ComputeMACAndEncode(token *RawJWT) (string, error) {
	signedToken, err := w.primary.mac.ComputeMACAndEncode(token)
	if err != nil {
		w.computeLogger.LogFailure()
		return "", err
	}
	w.computeLogger.Log(w.primary.keyID, 1)
	return signedToken, nil
}

func (w *wrappedJWTMAC) VerifyMACAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	var interestingErr error
	for _, macWithKeyID := range w.macs {
		mac, keyID := macWithKeyID.mac, macWithKeyID.keyID
		verifiedJWT, err := mac.VerifyMACAndDecode(compact, validator)
		if err == nil {
			w.verifyLogger.Log(keyID, 1)
			return verifiedJWT, nil
		}
		if err != errJwtVerification {
			// Any error that is not the generic errJwtVerification is considered
			// interesting.
			interestingErr = err
		}
	}
	w.verifyLogger.LogFailure()
	if interestingErr != nil {
		return nil, interestingErr
	}
	return nil, errJwtVerification
}
