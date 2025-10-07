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
	"bytes"
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/prefixmap"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(handle *keyset.Handle) (tink.Verifier, error) {
	ps, err := keyset.Primitives[tink.Verifier](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("verifier_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedVerifier(ps)
}

// verifierSet is a Verifier implementation that uses the
// underlying primitive set for verifying.
type wrappedVerifier struct {
	verifiers *prefixmap.PrefixMap[verifierAndID]
	logger    monitoring.Logger
}

type verifierAndID struct {
	verifier tink.Verifier
	keyID    uint32
}

func (a *verifierAndID) Verify(signatureBytes, data []byte) error {
	return a.verifier.Verify(signatureBytes, data)
}

// Asserts that verifierSet implements the Verifier interface.
var _ tink.Verifier = (*wrappedVerifier)(nil)

type fullVerifierAdapter struct {
	primitive        tink.Verifier
	prefix           []byte
	outputPrefixType tinkpb.OutputPrefixType
}

var _ tink.Verifier = (*fullVerifierAdapter)(nil)

func (a *fullVerifierAdapter) Verify(signatureBytes, data []byte) error {
	if !bytes.HasPrefix(signatureBytes, a.prefix) {
		return fmt.Errorf("verifier_factory: invalid signature prefix")
	}
	message := data
	if a.outputPrefixType == tinkpb.OutputPrefixType_LEGACY {
		message = slices.Concat(message, []byte{0})
	}
	return a.primitive.Verify(signatureBytes[len(a.prefix):], message)
}

// extractFullVerifier returns a [tink.Verifier] from the given entry as a
// "full" primitive.
//
// It wraps legacy primitives in a full primitive adapter.
func extractFullVerifier(e *primitiveset.Entry[tink.Verifier]) (tink.Verifier, error) {
	if e.FullPrimitive != nil {
		return e.FullPrimitive, nil
	}
	protoKey, err := protoserialization.SerializeKey(e.Key)
	if err != nil {
		return nil, err
	}
	prefixType := protoKey.OutputPrefixType()
	return &fullVerifierAdapter{
		primitive:        e.Primitive,
		prefix:           e.OutputPrefix(),
		outputPrefixType: prefixType,
	}, nil
}

func newWrappedVerifier(ps *primitiveset.PrimitiveSet[tink.Verifier]) (*wrappedVerifier, error) {
	verifiers := prefixmap.New[verifierAndID]()
	for _, entries := range ps.Entries {
		for _, e := range entries {
			verifier, err := extractFullVerifier(e)
			if err != nil {
				return nil, err
			}
			verifiers.Insert(string(e.OutputPrefix()), verifierAndID{
				verifier: verifier,
				keyID:    e.KeyID,
			})
		}
	}
	logger, err := createVerifierLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedVerifier{
		verifiers: verifiers,
		logger:    logger,
	}, nil
}

func createVerifierLogger(ps *primitiveset.PrimitiveSet[tink.Verifier]) (monitoring.Logger, error) {
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
		Primitive:   "public_key_verify",
		APIFunction: "verify",
	})
}

// Verify checks whether the given signature is a valid signature of the given data.
func (v *wrappedVerifier) Verify(signature, data []byte) error {
	it := v.verifiers.PrimitivesMatchingPrefix(signature)
	for verifier, ok := it.Next(); ok; verifier, ok = it.Next() {
		if err := verifier.Verify(signature, data); err != nil {
			continue
		}
		v.logger.Log(verifier.keyID, len(data))
		return nil
	}
	v.logger.LogFailure()
	return fmt.Errorf("verifier_factory: invalid signature")
}
