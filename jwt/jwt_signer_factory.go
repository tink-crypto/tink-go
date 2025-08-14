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

type signerWithKIDInterface interface {
	SignAndEncodeWithKID(*RawJWT, *string) (string, error)
}

// NewSigner generates a new instance of the JWT Signer primitive.
func NewSigner(handle *keyset.Handle) (Signer, error) {
	if handle == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	// WARNING: This is an all-or-nothing operation, meaning that *all* the keys
	// in the keyset must implement jwt.Signer. Until all JWT signature keys have
	// a primitive constructor, this is unused.
	ps, err := keyset.Primitives[Signer](handle, internalapi.Token{})
	if err != nil {
		// Try to obtain a signerWithKIDInterface primitive set.
		ps, err := keyset.Primitives[signerWithKIDInterface](handle, internalapi.Token{})
		if err != nil {
			return nil, fmt.Errorf("jwt_signer_factory: cannot obtain primitive set: %v", err)
		}
		logger, err := createSignerLogger(ps)
		if err != nil {
			return nil, err
		}

		if ps.Primary.Primitive == nil {
			// Something is wrong, this should not happen.
			return nil, fmt.Errorf("jwt_signer_factory: primary primitive is nil")
		}
		return &wrappedSigner{
			primaryFullPrimitive: &fullPrimitiveAdapter{
				primitive:  ps.Primary.Primitive,
				keyID:      ps.Primary.KeyID,
				prefixType: ps.Primary.PrefixType,
			},
			keyID:  ps.Primary.KeyID,
			logger: logger,
		}, nil
	}
	logger, err := createSignerLogger(ps)
	if err != nil {
		return nil, err
	}

	if ps.Primary.FullPrimitive == nil {
		// Something is wrong, this should not happen.
		return nil, fmt.Errorf("jwt_signer_factory: primary full primitive is nil")
	}

	return &wrappedSigner{
		primaryFullPrimitive: ps.Primary.FullPrimitive,
		keyID:                ps.Primary.KeyID,
		logger:               logger,
	}, nil
}

type fullPrimitiveAdapter struct {
	primitive  signerWithKIDInterface
	keyID      uint32
	prefixType tinkpb.OutputPrefixType
}

var _ Signer = (*fullPrimitiveAdapter)(nil)

func (a *fullPrimitiveAdapter) SignAndEncode(rawJWT *RawJWT) (string, error) {
	return a.primitive.SignAndEncodeWithKID(rawJWT, keyID(a.keyID, a.prefixType))
}

// wrappedSigner is a JWT Signer implementation that uses the underlying
// primary full primitive for signing. It logs success/failure of the signing
// operation.
type wrappedSigner struct {
	primaryFullPrimitive Signer
	keyID                uint32
	logger               monitoring.Logger
}

var _ Signer = (*wrappedSigner)(nil)

func createSignerLogger[T any](ps *primitiveset.PrimitiveSet[T]) (monitoring.Logger, error) {
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
		Primitive:   "jwtsign",
		APIFunction: "sign",
	})
}

func (w *wrappedSigner) SignAndEncode(rawJWT *RawJWT) (string, error) {
	token, err := w.primaryFullPrimitive.SignAndEncode(rawJWT)
	if err != nil {
		w.logger.LogFailure()
		return "", err
	}
	w.logger.Log(w.keyID, 1)
	return token, nil
}
