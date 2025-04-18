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

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// NewMAC generates a new instance of the JWT MAC primitive.
func NewMAC(handle *keyset.Handle) (MAC, error) {
	if handle == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	ps, err := keyset.Primitives[*macWithKID](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("jwt_mac_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedJWTMAC(ps)
}

// wrappedJWTMAC is a JWTMAC implementation that uses the underlying primitive set for JWT MAC.
type wrappedJWTMAC struct {
	ps            *primitiveset.PrimitiveSet[*macWithKID]
	computeLogger monitoring.Logger
	verifyLogger  monitoring.Logger
}

var _ MAC = (*wrappedJWTMAC)(nil)

func newWrappedJWTMAC(ps *primitiveset.PrimitiveSet[*macWithKID]) (*wrappedJWTMAC, error) {
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if p.PrefixType != tinkpb.OutputPrefixType_RAW && p.PrefixType != tinkpb.OutputPrefixType_TINK {
				return nil, fmt.Errorf("jwt_mac_factory: invalid OutputPrefixType: %s", p.PrefixType)
			}
		}
	}
	computeLogger, verifyLogger, err := createLoggers(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedJWTMAC{ps: ps, computeLogger: computeLogger, verifyLogger: verifyLogger}, nil
}

func createLoggers(ps *primitiveset.PrimitiveSet[*macWithKID]) (monitoring.Logger, monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, &monitoringutil.DoNothingLogger{}, nil
	}
	client := internalregistry.GetMonitoringClient()
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, nil, err
	}
	computeLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "jwtmac",
		APIFunction: "compute",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	verifyLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "jwtmac",
		APIFunction: "verify",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	return computeLogger, verifyLogger, nil
}

func (w *wrappedJWTMAC) ComputeMACAndEncode(token *RawJWT) (string, error) {
	primary := w.ps.Primary
	signedToken, err := primary.Primitive.ComputeMACAndEncodeWithKID(token, keyID(primary.KeyID, primary.PrefixType))
	if err != nil {
		w.computeLogger.LogFailure()
		return "", err
	}
	w.computeLogger.Log(primary.KeyID, 1)
	return signedToken, nil
}

func (w *wrappedJWTMAC) VerifyMACAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	var interestingErr error
	for _, s := range w.ps.Entries {
		for _, e := range s {
			verifiedJWT, err := e.Primitive.VerifyMACAndDecodeWithKID(compact, validator, keyID(e.KeyID, e.PrefixType))
			if err == nil {
				w.verifyLogger.Log(e.KeyID, 1)
				return verifiedJWT, nil
			}
			if err != errJwtVerification {
				// any error that is not the generic errJwtVerification is considered interesting
				interestingErr = err
			}
		}
	}
	w.verifyLogger.LogFailure()
	if interestingErr != nil {
		return nil, interestingErr
	}
	return nil, errJwtVerification
}
