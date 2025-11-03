// Copyright 2018 Google LLC
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

package signature

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// NewSigner returns a Signer primitive from the given keyset handle.
func NewSigner(handle *keyset.Handle) (tink.Signer, error) {
	ps, err := keyset.Primitives[tink.Signer](handle, &registryconfig.RegistryConfig{}, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("public_key_sign_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedSigner(ps)
}

// wrappedSigner is an Signer implementation that uses the underlying primitive set for signing.
type wrappedSigner struct {
	signer      tink.Signer
	signerKeyID uint32
	logger      monitoring.Logger
}

// Asserts that wrappedSigner implements the Signer interface.
var _ tink.Signer = (*wrappedSigner)(nil)

type fullSignerAdapter struct {
	primitive  tink.Signer
	prefix     []byte
	prefixType tinkpb.OutputPrefixType
}

var _ tink.Signer = (*fullSignerAdapter)(nil)

func (a *fullSignerAdapter) Sign(data []byte) ([]byte, error) {
	toSign := data
	if a.prefixType == tinkpb.OutputPrefixType_LEGACY {
		toSign = slices.Concat(data, []byte{0})
	}
	s, err := a.primitive.Sign(toSign)
	if err != nil {
		return nil, err
	}
	return slices.Concat(a.prefix, s), nil
}

// extractFullSigner returns a [tink.Signer] from the given entry as a "full"
// primitive.
//
// It wraps legacy primitives in a full primitive adapter.
func extractFullSigner(e *primitiveset.Entry[tink.Signer]) (tink.Signer, error) {
	if e.FullPrimitive != nil {
		return e.FullPrimitive, nil
	}
	protoKey, err := protoserialization.SerializeKey(e.Key)
	if err != nil {
		return nil, err
	}
	return &fullSignerAdapter{
		primitive:  e.Primitive,
		prefix:     e.OutputPrefix(),
		prefixType: protoKey.OutputPrefixType(),
	}, nil
}

func newWrappedSigner(ps *primitiveset.PrimitiveSet[tink.Signer]) (*wrappedSigner, error) {
	signer, err := extractFullSigner(ps.Primary)
	if err != nil {
		return nil, err
	}
	logger, err := createSignerLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedSigner{
		signer:      signer,
		signerKeyID: ps.Primary.KeyID,
		logger:      logger,
	}, nil
}

func createSignerLogger(ps *primitiveset.PrimitiveSet[tink.Signer]) (monitoring.Logger, error) {
	// Only keysets which contain annotations are monitored.
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, nil
	}
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, err
	}
	return internalregistry.GetMonitoringClient().NewLogger(&monitoring.Context{
		KeysetInfo:  keysetInfo,
		Primitive:   "public_key_sign",
		APIFunction: "sign",
	})
}

// Sign signs the given data using the primary key.
func (s *wrappedSigner) Sign(data []byte) ([]byte, error) {
	signature, err := s.signer.Sign(data)
	if err != nil {
		s.logger.LogFailure()
		return nil, err
	}
	s.logger.Log(s.signerKeyID, len(data))
	return signature, nil
}
