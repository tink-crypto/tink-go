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

	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// New returns a StreamingAEAD primitive from the given keyset handle.
func New(handle *keyset.Handle) (tink.StreamingAEAD, error) {
	ps, err := keyset.Primitives[tink.StreamingAEAD](handle, internalapi.Token{})
	if err != nil {
		return nil, fmt.Errorf("streamingaead_factory: cannot obtain primitive set: %s", err)
	}
	ret := new(wrappedStreamingAEAD)
	ret.ps = ps
	return tink.StreamingAEAD(ret), nil
}

// wrappedStreamingAEAD is a StreamingAEAD implementation that uses the underlying primitive set
// for streaming encryption and decryption.
type wrappedStreamingAEAD struct {
	ps *primitiveset.PrimitiveSet[tink.StreamingAEAD]
}

// Asserts that wrappedStreamingAEAD implements the StreamingAEAD interface.
var _ tink.StreamingAEAD = (*wrappedStreamingAEAD)(nil)

// NewEncryptingWriter returns a wrapper around underlying io.Writer, such that any write-operation
// via the wrapper results in AEAD-encryption of the written data, using aad
// as associated authenticated data. The associated data is not included in the ciphertext
// and has to be passed in as parameter for decryption.
func (s *wrappedStreamingAEAD) NewEncryptingWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	primary := s.ps.Primary
	return primary.Primitive.NewEncryptingWriter(w, aad)
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
