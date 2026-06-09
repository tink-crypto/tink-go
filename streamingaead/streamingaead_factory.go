// Copyright 2020 Google LLC
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

package streamingaead

import (
	"fmt"
	"io"

	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// New returns a [tink.StreamingAEAD] primitive from the given keyset handle using
// the global registry.
func New(handle *keyset.Handle) (tink.StreamingAEAD, error) {
	return NewWithConfig(handle, &registryconfig.RegistryConfig{})
}

// NewWithConfig returns a [tink.StreamingAEAD] primitive from the given keyset
// handle with the provided [keyset.Config].
func NewWithConfig(handle *keyset.Handle, config keyset.Config) (tink.StreamingAEAD, error) {
	if handle.Len() == 0 {
		return nil, fmt.Errorf("streamingaead_factory: empty or nil keyset handle")
	}
	var primitives []tink.StreamingAEAD
	var primary tink.StreamingAEAD

	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		// We ignore the boolean indicating whether the primitive is a legacy
		// "non-full" primitive, because Streaming AEAD primitives are always
		// without output prefix.
		primitive, _, err := factoryutil.PrimitiveFromKey[tink.StreamingAEAD](entry.Key(), config)
		if err != nil {
			return nil, err
		}
		primitives = append(primitives, primitive)
		if entry.IsPrimary() {
			primary = primitive
		}
	}

	return &wrappedStreamingAEAD{
		primary:    primary,
		primitives: primitives,
	}, nil
}

// wrappedStreamingAEAD is a StreamingAEAD implementation that uses the underlying primitive set
// for streaming encryption and decryption.
type wrappedStreamingAEAD struct {
	primary    tink.StreamingAEAD
	primitives []tink.StreamingAEAD
}

// Asserts that wrappedStreamingAEAD implements the StreamingAEAD interface.
var _ tink.StreamingAEAD = (*wrappedStreamingAEAD)(nil)

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that any write-operation
// via the wrapper results in AEAD-encryption of the written data, using aad
// as associated authenticated data. The associated data is not included in the ciphertext
// and has to be passed in as parameter for decryption.
func (s *wrappedStreamingAEAD) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	return s.primary.NewEncryptingWriter(w, aad)
}

// NewDecryptingReader returns a wrapper around underlying io.Reader, such that any read-operation
// via the wrapper results in AEAD-decryption of the underlying ciphertext,
// using aad as associated authenticated data.
func (s *wrappedStreamingAEAD) NewDecryptingReader(r io.Reader, aad []byte) (io.Reader, error) {
	return &decryptReader{
		wrapped: s,
		cr:      r,
		aad:     aad,
	}, nil
}
