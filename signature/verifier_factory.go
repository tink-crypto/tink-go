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

	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/prefixmap"
	"github.com/tink-crypto/tink-go/v2/internal/protoserialization"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"

	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// NewVerifierWithConfig returns a [tink.Verifier] primitive from the given
// [keyset.Handle] and [keyset.Config].
func NewVerifierWithConfig(handle *keyset.Handle, config keyset.Config) (tink.Verifier, error) {
	if handle.Len() == 0 {
		return nil, fmt.Errorf("verifier_factory: empty or nil keyset handle")
	}
	verifiers := prefixmap.New[verifierAndID]()
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		verifier, isLegacyPrimitive, err := factoryutil.PrimitiveFromKey[tink.Verifier](entry.Key(), config)
		if err != nil {
			// Using this error message for backwards compatibility with existing clients.
			return nil, fmt.Errorf("verifier_factory: cannot obtain primitive set: %s", err)
		}

		outputPrefix, err := factoryutil.OutputPrefix(entry.Key())
		if err != nil {
			return nil, err
		}

		if isLegacyPrimitive {
			hasLegacyPrefix := false
			if bytes.HasPrefix(outputPrefix, []byte{cryptofmt.LegacyStartByte}) { // CRUNCHY or LEGACY
				protoKey, err := protoserialization.SerializeKey(entry.Key())
				if err != nil {
					return nil, err
				}
				hasLegacyPrefix = protoKey.OutputPrefixType() == tinkpb.OutputPrefixType_LEGACY
			}
			verifier = &fullVerifierAdapter{
				primitive:       verifier,
				prefix:          outputPrefix,
				hasLegacyPrefix: hasLegacyPrefix,
			}
		}

		verifiers.Insert(string(outputPrefix), verifierAndID{
			verifier: verifier,
			keyID:    entry.KeyID(),
		})
	}
	logger, err := createVerifierLogger(handle)
	if err != nil {
		return nil, err
	}
	return &wrappedVerifier{
		verifiers: verifiers,
		logger:    logger,
	}, nil
}

// NewVerifier returns a [tink.Verifier] primitive from the given
// [keyset.Handle].
func NewVerifier(handle *keyset.Handle) (tink.Verifier, error) {
	return NewVerifierWithConfig(handle, &registryconfig.RegistryConfig{})
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
	primitive       tink.Verifier
	prefix          []byte
	hasLegacyPrefix bool
}

var _ tink.Verifier = (*fullVerifierAdapter)(nil)

func (a *fullVerifierAdapter) Verify(signatureBytes, data []byte) error {
	if !bytes.HasPrefix(signatureBytes, a.prefix) {
		return fmt.Errorf("verifier_factory: invalid signature prefix")
	}
	message := data
	if a.hasLegacyPrefix {
		message = slices.Concat(message, []byte{0})
	}
	return a.primitive.Verify(signatureBytes[len(a.prefix):], message)
}

func createVerifierLogger(kh *keyset.Handle) (monitoring.Logger, error) {
	factory, err := factoryutil.NewLoggerFactory(kh)
	if err != nil {
		return nil, err
	}
	return factory.CreateFor("public_key_verify", "verify")
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
