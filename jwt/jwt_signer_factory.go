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

// NewSigner generates a new instance of the JWT Signer primitive.
func NewSigner(handle *keyset.Handle) (Signer, error) {
	if handle == nil {
		return nil, fmt.Errorf("keyset handle can't be nil")
	}
	ps, err := keyset.Primitives[*signerWithKID](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("jwt_signer_factory: cannot obtain primitive set: %v", err)
	}
	return newWrappedSigner(ps)
}

// wrappedSigner is a JWT Signer implementation that uses the underlying primitive set for JWT Sign.
type wrappedSigner struct {
	ps     *primitiveset.PrimitiveSet[*signerWithKID]
	logger monitoring.Logger
}

var _ Signer = (*wrappedSigner)(nil)

func createSignerLogger(ps *primitiveset.PrimitiveSet[*signerWithKID]) (monitoring.Logger, error) {
	// only keysets which contain annotations are monitored.
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

func newWrappedSigner(ps *primitiveset.PrimitiveSet[*signerWithKID]) (*wrappedSigner, error) {
	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if p.PrefixType != tinkpb.OutputPrefixType_RAW && p.PrefixType != tinkpb.OutputPrefixType_TINK {
				return nil, fmt.Errorf("jwt_signer_factory: invalid OutputPrefixType: %s", p.PrefixType)
			}
		}
	}
	logger, err := createSignerLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedSigner{
		ps:     ps,
		logger: logger,
	}, nil
}

func (w *wrappedSigner) SignAndEncode(rawJWT *RawJWT) (string, error) {
	primary := w.ps.Primary
	token, err := primary.Primitive.SignAndEncodeWithKID(rawJWT, keyID(primary.KeyID, primary.PrefixType))
	if err != nil {
		w.logger.LogFailure()
		return "", err
	}
	w.logger.Log(primary.KeyID, 1)
	return token, nil
}
