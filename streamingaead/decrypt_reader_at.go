// Copyright 2025 Google LLC
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
	"sync/atomic"

	"github.com/tink-crypto/tink-go/v2/internal/factoryutil"
	"github.com/tink-crypto/tink-go/v2/internal/registryconfig"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle/noncebased"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// SizedReaderAt combines io.ReaderAt with a Size method reporting the total
// number of bytes available. *bytes.Reader and *io.SectionReader implement this
// interface.
type SizedReaderAt interface {
	io.ReaderAt
	Size() int64
}

// readerAtAEAD is implemented by streaming AEAD primitives that support
// random-access decryption.
type readerAtAEAD interface {
	NewDecryptingReaderAt(ct io.ReaderAt, ctSize int64, aad []byte) (*noncebased.ReaderAt, error)
	HeaderLength() int
}

type readerAtCandidate struct {
	r      *noncebased.ReaderAt
	hdrLen int
}

// DecryptingReaderAt provides random access to the plaintext of a streaming
// AEAD ciphertext.
//
// It satisfies io.ReaderAt and is safe for concurrent use; ReadAt calls execute
// in parallel. A single decrypted ciphertext segment is cached, so sequential
// reads within one segment do not repeat decryption.
type DecryptingReaderAt struct {
	candidates []readerAtCandidate
	matched    atomic.Pointer[readerAtCandidate]
}

var _ io.ReaderAt = (*DecryptingReaderAt)(nil)

// NewDecryptingReaderAt returns a DecryptingReaderAt that decrypts the
// ciphertext available via ct using the keys in handle and aad as associated
// authenticated data.
//
// The ciphertext header is read eagerly during construction. For keysets
// containing multiple keys, the correct key is identified lazily on the first
// ReadAt call: each candidate key is tried in keyset order until one
// authenticates the requested segment.
//
// ct must provide the full ciphertext stream as written by an encrypting
// writer obtained from New, and ct.Size() must return its exact length.
func NewDecryptingReaderAt(handle *keyset.Handle, ct SizedReaderAt, aad []byte) (*DecryptingReaderAt, error) {
	if handle.Len() == 0 {
		return nil, fmt.Errorf("streamingaead: empty or nil keyset handle")
	}
	config := &registryconfig.RegistryConfig{}

	ctSize := ct.Size()
	var candidates []readerAtCandidate
	for entry := range factoryutil.EnabledUnmonitoredEntries(handle) {
		// Streaming AEAD primitives are always without output prefix, so the
		// boolean indicating a legacy "non-full" primitive is ignored.
		primitive, _, err := factoryutil.PrimitiveFromKey[tink.StreamingAEAD](entry.Key(), config)
		if err != nil {
			return nil, err
		}
		ra, ok := primitive.(readerAtAEAD)
		if !ok {
			continue
		}
		r, err := ra.NewDecryptingReaderAt(ct, ctSize, aad)
		if err != nil {
			continue
		}
		candidates = append(candidates, readerAtCandidate{r: r, hdrLen: ra.HeaderLength()})
	}
	if len(candidates) == 0 {
		return nil, errKeyNotFound
	}
	return &DecryptingReaderAt{candidates: candidates}, nil
}

// ReadAt decrypts and returns plaintext bytes at the given offset.
func (d *DecryptingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		// A zero-length read decrypts nothing, so it cannot tell the
		// candidate keys apart. Answering it directly keeps it from
		// selecting one at random.
		return 0, nil
	}
	if c := d.matched.Load(); c != nil {
		return c.r.ReadAt(p, off)
	}
	for i := range d.candidates {
		// A candidate that reports io.EOF has decrypted the final segment,
		// which only the encrypting key can do, so it is as conclusive a
		// match as a successful read.
		n, err := d.candidates[i].r.ReadAt(p, off)
		if err == nil || err == io.EOF {
			d.matched.Store(&d.candidates[i])
			return n, err
		}
	}
	return 0, errKeyNotFound
}

// selected returns the matched candidate once known, otherwise the first
// candidate.
func (d *DecryptingReaderAt) selected() *readerAtCandidate {
	if c := d.matched.Load(); c != nil {
		return c
	}
	return &d.candidates[0]
}

// Size returns the size of the plaintext.
//
// The returned value is derived from the length of the ciphertext, which is
// not itself authenticated: a truncated stream yields a smaller size. A read
// that reaches the end of the plaintext decrypts the final segment and so
// fails on a truncated stream, which makes reading the whole plaintext, or a
// single byte at Size()-1, sufficient to establish that the size is genuine.
//
// For keysets containing multiple keys, the value reported before the first
// ReadAt is computed from the first candidate key's parameters.
func (d *DecryptingReaderAt) Size() int64 {
	return d.selected().r.Size()
}

// CiphertextRange returns the byte range [off, off+n) within the ciphertext
// passed to NewDecryptingReaderAt that ReadAt will access in order to satisfy a
// plaintext read of [ptOff, ptOff+ptLen). Callers backed by remote storage can
// use this to prefetch the required bytes in a single round trip.
//
// The returned range covers whole ciphertext segments and does not include the
// stream header (which has already been read at construction time). For keysets
// containing keys with heterogeneous segment-size or header-length parameters,
// the value reported before the first successful ReadAt is computed from the
// first candidate key's parameters and may not match the encrypting key's
// layout; in that case, perform a single small ReadAt first to lock in the
// correct key.
func (d *DecryptingReaderAt) CiphertextRange(ptOff, ptLen int64) (off, n int64) {
	c := d.selected()
	off, n = c.r.CiphertextRange(ptOff, ptLen)
	if n == 0 {
		return 0, 0
	}
	return off + int64(c.hdrLen), n
}
