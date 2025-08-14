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

type verifierAndKeyID struct {
	verifier Verifier
	keyID    uint32
}

type verifierWithKIDInterface interface {
	VerifyAndDecodeWithKID(compact string, validator *Validator, kid *string) (*VerifiedJWT, error)
}

type fullVerifierAdapter struct {
	verifierWithKID verifierWithKIDInterface
	keyID           uint32
	prefixType      tinkpb.OutputPrefixType
}

var _ Verifier = (*fullVerifierAdapter)(nil)

func (a *fullVerifierAdapter) VerifyAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	return a.verifierWithKID.VerifyAndDecodeWithKID(compact, validator, keyID(a.keyID, a.prefixType))
}

// NewVerifier generates a new instance of the JWT Verifier primitive.
func NewVerifier(handle *keyset.Handle) (Verifier, error) {
	if handle == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	var verifiers []verifierAndKeyID
	var logger monitoring.Logger
	// Try to obtain full primitives first. If it fails, likely because there is no
	// full primitive constructor registered, fall back to the "raw"
	// verifierWithKIDInterface primitives.
	ps, err := keyset.Primitives[Verifier](handle, internalapi.Token{})
	if err != nil {
		// Try to obtain a verifierWithKIDInterface primitive set.
		ps, err := keyset.Primitives[verifierWithKIDInterface](handle, internalapi.Token{})
		if err != nil {
			return nil, fmt.Errorf("jwt_verifier_factory: cannot obtain primitive set: %v", err)
		}
		logger, err = createVerifierLogger(ps)
		if err != nil {
			return nil, err
		}
		for _, primitives := range ps.Entries {
			for _, p := range primitives {
				if p.Primitive == nil {
					// Something is wrong, this should not happen.
					return nil, fmt.Errorf("jwt_verifier_factory: primary primitive is nil")
				}
				verifiers = append(verifiers, verifierAndKeyID{
					verifier: &fullVerifierAdapter{
						verifierWithKID: p.Primitive,
						keyID:           p.KeyID,
						prefixType:      p.PrefixType,
					},
					keyID: p.KeyID,
				})
			}
		}
	} else {
		logger, err = createVerifierLogger(ps)
		if err != nil {
			return nil, err
		}
		for _, primitives := range ps.Entries {
			for _, p := range primitives {
				if p.FullPrimitive == nil {
					// Something is wrong, this should not happen.
					return nil, fmt.Errorf("jwt_verifier_factory: primary full primitive is nil")
				}
				verifiers = append(verifiers, verifierAndKeyID{
					verifier: p.FullPrimitive,
					keyID:    p.KeyID,
				})
			}
		}
	}
	return &wrappedVerifier{
		verifiers: verifiers,
		logger:    logger,
	}, nil
}

func createVerifierLogger[T any](ps *primitiveset.PrimitiveSet[T]) (monitoring.Logger, error) {
	// Only keysets with annotations are monitored.
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "jwtverify",
		APIFunction: "verify",
	})
}

// wrappedVerifier is a JWT Verifier implementation that tries all the available
// verifiers and returns the first success, if any. It Logs success/filure.
type wrappedVerifier struct {
	verifiers []verifierAndKeyID
	logger    monitoring.Logger
}

var _ Verifier = (*wrappedVerifier)(nil)

func (w *wrappedVerifier) VerifyAndDecode(compact string, validator *Validator) (*VerifiedJWT, error) {
	var interestingErr error
	for _, verifierWithKeyID := range w.verifiers {
		verifier, keyID := verifierWithKeyID.verifier, verifierWithKeyID.keyID
		verifiedJWT, err := verifier.VerifyAndDecode(compact, validator)
		if err != nil {
			if err != errJwtVerification {
				// Any error that is not the generic errJwtVerification is considered
				// interesting.
				interestingErr = err
			}
			continue
		}
		w.logger.Log(keyID, 1)
		return verifiedJWT, nil
	}
	w.logger.LogFailure()
	if interestingErr != nil {
		return nil, interestingErr
	}
	return nil, errJwtVerification
}
