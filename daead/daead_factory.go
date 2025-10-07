// Copyright 2019 Google LLC
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

package daead

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/internalregistry"
	"github.com/tink-crypto/tink-go/v2/internal/monitoringutil"
	"github.com/tink-crypto/tink-go/v2/internal/prefixmap"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/monitoring"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// New returns a DeterministicAEAD primitive from the given keyset handle.
func New(handle *keyset.Handle) (tink.DeterministicAEAD, error) {
	ps, err := keyset.Primitives[tink.DeterministicAEAD](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("daead_factory: cannot obtain primitive set: %s", err)
	}
	return newWrappedDeterministicAEAD(ps)
}

type daeadAndKeyID struct {
	primitive tink.DeterministicAEAD
	keyID     uint32
}

func (a *daeadAndKeyID) EncryptDeterministically(plaintext, associatedData []byte) ([]byte, error) {
	return a.primitive.EncryptDeterministically(plaintext, associatedData)
}

func (a *daeadAndKeyID) DecryptDeterministically(ciphertext, associatedData []byte) ([]byte, error) {
	return a.primitive.DecryptDeterministically(ciphertext, associatedData)
}

// fullDAEADPrimitiveAdapter is an adapter that turns a non-full [tink.DAEAD]
// primitive into a full [tink.DAEAD] primitive.
type fullDAEADPrimitiveAdapter struct {
	primitive tink.DeterministicAEAD
	prefix    []byte
}

var _ tink.DeterministicAEAD = (*fullDAEADPrimitiveAdapter)(nil)

func (a *fullDAEADPrimitiveAdapter) EncryptDeterministically(plaintext, associatedData []byte) ([]byte, error) {
	ct, err := a.primitive.EncryptDeterministically(plaintext, associatedData)
	if err != nil {
		return nil, err
	}
	return slices.Concat(a.prefix, ct), nil
}

func (a *fullDAEADPrimitiveAdapter) DecryptDeterministically(ciphertext, associatedData []byte) ([]byte, error) {
	return a.primitive.DecryptDeterministically(ciphertext[len(a.prefix):], associatedData)
}

func extractFullDAEAD(entry *primitiveset.Entry[tink.DeterministicAEAD]) (*daeadAndKeyID, error) {
	if entry.FullPrimitive != nil {
		return &daeadAndKeyID{
			primitive: entry.FullPrimitive,
			keyID:     entry.KeyID,
		}, nil
	}
	return &daeadAndKeyID{
		primitive: &fullDAEADPrimitiveAdapter{
			primitive: entry.Primitive,
			prefix:    entry.OutputPrefix(),
		},
		keyID: entry.KeyID,
	}, nil
}

// wrappedDAEAD is a DeterministicAEAD implementation that uses an underlying
// primitive set for deterministic encryption and decryption.
type wrappedDAEAD struct {
	primary    daeadAndKeyID
	primitives *prefixmap.PrefixMap[daeadAndKeyID]

	encLogger monitoring.Logger
	decLogger monitoring.Logger
}

var _ tink.DeterministicAEAD = (*wrappedDAEAD)(nil)

func newWrappedDeterministicAEAD(ps *primitiveset.PrimitiveSet[tink.DeterministicAEAD]) (*wrappedDAEAD, error) {
	primary, err := extractFullDAEAD(ps.Primary)
	if err != nil {
		return nil, err
	}
	primitives := prefixmap.New[daeadAndKeyID]()
	for _, entries := range ps.Entries {
		for _, entry := range entries {
			p, err := extractFullDAEAD(entry)
			if err != nil {
				return nil, err
			}
			primitives.Insert(string(entry.OutputPrefix()), *p)
		}
	}

	encLogger, decLogger, err := createLoggers(ps)
	if err != nil {
		return nil, err
	}
	return &wrappedDAEAD{
		primary:    *primary,
		primitives: primitives,
		encLogger:  encLogger,
		decLogger:  decLogger,
	}, nil
}

func createLoggers(ps *primitiveset.PrimitiveSet[tink.DeterministicAEAD]) (monitoring.Logger, monitoring.Logger, error) {
	if len(ps.Annotations) == 0 {
		return &monitoringutil.DoNothingLogger{}, &monitoringutil.DoNothingLogger{}, nil
	}
	client := internalregistry.GetMonitoringClient()
	keysetInfo, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		return nil, nil, err
	}
	encLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "daead",
		APIFunction: "encrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	decLogger, err := client.NewLogger(&monitoring.Context{
		Primitive:   "daead",
		APIFunction: "decrypt",
		KeysetInfo:  keysetInfo,
	})
	if err != nil {
		return nil, nil, err
	}
	return encLogger, decLogger, nil
}

// EncryptDeterministically deterministically encrypts plaintext with additionalData as additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (d *wrappedDAEAD) EncryptDeterministically(pt, aad []byte) ([]byte, error) {
	ct, err := d.primary.EncryptDeterministically(pt, aad)
	if err != nil {
		d.encLogger.LogFailure()
		return nil, err
	}
	d.encLogger.Log(d.primary.keyID, len(pt))
	return ct, nil
}

// DecryptDeterministically deterministically decrypts ciphertext with additionalData as
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (d *wrappedDAEAD) DecryptDeterministically(ct, aad []byte) ([]byte, error) {
	it := d.primitives.PrimitivesMatchingPrefix(ct)
	for decrypter, ok := it.Next(); ok; decrypter, ok = it.Next() {
		pt, err := decrypter.DecryptDeterministically(ct, aad)
		if err != nil {
			continue
		}
		d.decLogger.Log(decrypter.keyID, len(ct))
		return pt, nil
	}
	// Nothing worked.
	d.decLogger.LogFailure()
	return nil, fmt.Errorf("daead_factory: decryption failed")
}
