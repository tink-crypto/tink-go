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
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(handle *keyset.Handle) (tink.Verifier, error) {
	ps, err := handle.Primitives(internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("verifier_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedVerifier(ps)
}

// verifierSet is a Verifier implementation that uses the
// underlying primitive set for verifying.
type wrappedVerifier struct {
	ps     *primitiveset.PrimitiveSet
	logger monitoring.Logger
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
func extractFullVerifier(entry *primitiveset.Entry) (tink.Verifier, error) {
	if entry.FullPrimitive != nil {
		p, ok := (entry.FullPrimitive).(tink.Verifier)
		if !ok {
			return nil, fmt.Errorf("verifier_factory: not a Verifier full primitive")
		}
		return p, nil
	}
	p, ok := (entry.Primitive).(tink.Verifier)
	if !ok {
		return nil, fmt.Errorf("verifier_factory: not a Verifier primitive")
	}
	return &fullVerifierAdapter{
		primitive:        p,
		prefix:           []byte(entry.Prefix),
		outputPrefixType: entry.PrefixType,
	}, nil
}

func newWrappedVerifier(ps *primitiveset.PrimitiveSet) (*wrappedVerifier, error) {
	if _, err := extractFullVerifier(ps.Primary); err != nil {
		return nil, err
	}
	for _, entries := range ps.Entries {
		for _, entry := range entries {
			if _, err := extractFullVerifier(entry); err != nil {
				return nil, err
			}
		}
	}
	logger, err := createVerifierLogger(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedVerifier{
		ps:     ps,
		logger: logger,
	}, nil
}

func createVerifierLogger(ps *primitiveset.PrimitiveSet) (monitoring.Logger, error) {
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
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(signature) < prefixSize {
		return fmt.Errorf("verifier_factory: invalid signature; expected at least %d bytes, got %d", prefixSize, len(signature))
	}
	// Try to verify with non-raw keys.
	entries, _ := v.ps.EntriesForPrefix(string(signature[:prefixSize]))
	for _, entry := range entries {
		verifier, err := extractFullVerifier(entry)
		if err != nil {
			return err
		}
		if err = verifier.Verify(signature, data); err == nil {
			v.logger.Log(entry.KeyID, len(data))
			return nil
		}
	}
	// Try to verify with raw keys.
	entries, _ = v.ps.RawEntries()
	for _, entry := range entries {
		verifier, err := extractFullVerifier(entry)
		if err != nil {
			return err
		}
		if err = verifier.Verify(signature, data); err == nil {
			v.logger.Log(entry.KeyID, len(data))
			return nil
		}
	}
	v.logger.LogFailure()
	return fmt.Errorf("verifier_factory: invalid signature")
}
