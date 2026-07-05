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

// Package noncebased provides a reusable streaming AEAD framework.
//
// It tackles the segment handling portions of the nonce based online
// encryption scheme proposed in "Online Authenticated-Encryption and its
// Nonce-Reuse Misuse-Resistance" by Hoang, Reyhanitabar, Rogaway and Vizár
// (https://eprint.iacr.org/2015/189.pdf).
//
// In this scheme, the format of a ciphertext is:
//
//	header || segment_0 || segment_1 || ... || segment_k.
//
// The format of header is:
//
//	headerLength || salt || nonce_prefix
//
// headerLength is 1 byte which documents the size of the header and can be
// obtained via HeaderLength(). In principle, headerLength is redundant
// information, since the length of the header can be determined from the key
// size.
//
// salt is a salt used in the key derivation.
//
// nonce_prefix is a prefix for all per-segment nonces.
//
// segment_i is the i-th segment of the ciphertext. The size of segment_1 ..
// segment_{k-1} is ciphertextSegmentSize. segment_0 is shorter, so that
// segment_0 plus additional data of size firstCiphertextSegmentOffset (e.g.
// the header) aligns with ciphertextSegmentSize.
//
// The first segment size will be:
//
//	ciphertextSegmentSize - HeaderLength() - firstCiphertextSegmentOffset.
package noncebased

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

var (
	// ErrNonceSizeTooShort indicates that the specified nonce size isn't large
	// enough to hold the nonce prefix, counter and last segment flag.
	ErrNonceSizeTooShort = errors.New("nonce size too short")

	// ErrCiphertextSegmentTooShort indicates the the ciphertext segment being
	// processed is too short.
	ErrCiphertextSegmentTooShort = errors.New("ciphertext segment too short")

	// ErrTooManySegments indicates that the ciphertext has too many segments.
	ErrTooManySegments = errors.New("too many segments")
)

// SegmentEncrypter facilitates implementing various streaming AEAD encryption
// modes.
type SegmentEncrypter interface {
	// EncryptSegment encrypts segment using nonce.
	EncryptSegment(segment, nonce []byte) ([]byte, error)
}

// This is a slightly more general API of SegmentEnrypter that is more efficient because
// it requires less memory allocations. It is currently not a stable API and is Tink internal.
type segmentEncrypterWithDst interface {
	// EncryptSegmentWithDst does the same as EncryptSegment, but will store the result in `dst` if
	// `cap(dst)` is large enough.
	//
	// An error will be returned if `len(dst)` is not 0.
	EncryptSegmentWithDst(dst, segment, nonce []byte) ([]byte, error)
}

// Writer provides a framework for ingesting plaintext data and
// writing encrypted data to the wrapped io.Writer. The scheme used for
// encrypting segments is specified by providing a SegmentEncrypter
// implementation.
type Writer struct {
	w                            io.Writer
	segmentEncrypter             SegmentEncrypter
	segmentEncrypterWithDst      segmentEncrypterWithDst
	useSegmentEncrypterWithDst   bool
	encryptedSegmentCnt          uint64
	firstCiphertextSegmentOffset int
	nonceSize                    int
	noncePrefix                  []byte
	plaintext                    []byte
	plaintextPos                 int
	// plaintextBufferLimit is the full plaintext segment size. w.plaintext
	// starts small and grows toward this limit only if data actually
	// arrives.
	plaintextBufferLimit int
	ciphertext           []byte
	closed               bool
}

// WriterParams contains the options for instantiating a Writer via NewWriter().
type WriterParams struct {
	// W is the underlying writer being wrapped.
	W io.Writer

	// SegmentEncrypter provides a method for encrypting segments.
	SegmentEncrypter SegmentEncrypter

	// NonceSize is the length of generated nonces. It must be at least 5 +
	// len(NoncePrefix). It can be longer, but longer nonces introduce more
	// overhead in the resultant ciphertext.
	NonceSize int

	// NoncePrefix is a constant that all nonces throughout the ciphertext will
	// start with. It's length must be at least 5 bytes shorter than NonceSize.
	NoncePrefix []byte

	// The size of the segments which the plaintext will be split into.
	PlaintextSegmentSize int

	// FirstCiphertexSegmentOffset indicates where the ciphertext should begin in
	// W. This allows for the existence of overhead in the stream unrelated to
	// this encryption scheme.
	FirstCiphertextSegmentOffset int
}

// NewWriter creates a new Writer instance.
func NewWriter(params WriterParams) (*Writer, error) {
	if params.NonceSize-len(params.NoncePrefix) < 5 {
		return nil, ErrNonceSizeTooShort
	}

	// If params.SegmentEncrypter implements method EncryptSegmentWithDst, then we use that because it
	// is more efficient.
	encrypterWithDst, useEncrypterWithDst := params.SegmentEncrypter.(segmentEncrypterWithDst)

	return &Writer{
		w:                            params.W,
		segmentEncrypter:             params.SegmentEncrypter,
		segmentEncrypterWithDst:      encrypterWithDst,
		useSegmentEncrypterWithDst:   useEncrypterWithDst,
		nonceSize:                    params.NonceSize,
		noncePrefix:                  params.NoncePrefix,
		firstCiphertextSegmentOffset: params.FirstCiphertextSegmentOffset,

		// The buffer must be able to hold a full plaintext segment, but is
		// allocated small and grown as data actually arrives, so that
		// plaintexts much smaller than the segment size do not pay for a
		// full segment-sized allocation.
		plaintext:            make([]byte, initialSegmentBufferSize(params.PlaintextSegmentSize)),
		plaintextBufferLimit: params.PlaintextSegmentSize,
	}, nil
}

// Write encrypts passed data and passes the encrypted data to the underlying writer.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write on closed writer")
	}

	pos := 0
	for {
		ptLim := w.plaintextBufferLimit
		if w.encryptedSegmentCnt == 0 {
			if w.firstCiphertextSegmentOffset < 0 || w.firstCiphertextSegmentOffset > w.plaintextBufferLimit {
				// A FirstCiphertextSegmentOffset outside the interval
				// [0, PlaintextSegmentSize] cannot yield a valid first
				// segment. The keyset-based streamingaead API never
				// constructs such a Writer, but the exported subtle
				// constructors only bound the offset from above.
				return pos, errors.New("first ciphertext segment offset out of range")
			}
			ptLim -= w.firstCiphertextSegmentOffset
		}
		copyLim := min(ptLim, len(w.plaintext))
		n := copy(w.plaintext[w.plaintextPos:copyLim], p[pos:])
		w.plaintextPos += n
		pos += n
		if pos == len(p) {
			break
		}

		if w.plaintextPos < ptLim {
			// The buffer is full but the segment is not complete: grow
			// toward the full segment size, no less than the buffered data
			// plus the data still pending in p, so that a single large
			// Write skips the intermediate growth steps.
			needed := w.plaintextPos + len(p) - pos
			grown := make([]byte, grownSegmentBufferSize(len(w.plaintext), needed, w.plaintextBufferLimit))
			copy(grown, w.plaintext[:w.plaintextPos])
			w.plaintext = grown
			continue
		}

		nonce, err := generateSegmentNonce(w.nonceSize, w.noncePrefix, w.encryptedSegmentCnt, false)
		if err != nil {
			return pos, err
		}
		if w.useSegmentEncrypterWithDst {
			w.ciphertext, err = w.segmentEncrypterWithDst.EncryptSegmentWithDst(w.ciphertext[:0], w.plaintext[:ptLim], nonce)
		} else {
			w.ciphertext, err = w.segmentEncrypter.EncryptSegment(w.plaintext[:ptLim], nonce)
		}
		if err != nil {
			return pos, err
		}

		if _, err := w.w.Write(w.ciphertext); err != nil {
			return pos, err
		}

		w.plaintextPos = 0
		w.encryptedSegmentCnt++
	}
	return pos, nil
}

// Close encrypts the remaining data, flushes it to the underlying writer and
// closes this writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}

	nonce, err := generateSegmentNonce(w.nonceSize, w.noncePrefix, w.encryptedSegmentCnt, true)
	if err != nil {
		return err
	}
	if w.useSegmentEncrypterWithDst {
		w.ciphertext, err = w.segmentEncrypterWithDst.EncryptSegmentWithDst(w.ciphertext[:0], w.plaintext[:w.plaintextPos], nonce)
	} else {
		w.ciphertext, err = w.segmentEncrypter.EncryptSegment(w.plaintext[:w.plaintextPos], nonce)
	}
	if err != nil {
		return err
	}

	if _, err := w.w.Write(w.ciphertext); err != nil {
		return err
	}

	w.plaintextPos = 0
	w.encryptedSegmentCnt++
	w.closed = true
	return nil
}

// SegmentDecrypter facilitates implementing various streaming AEAD encryption modes.
type SegmentDecrypter interface {
	// DecryptSegment decrypts segment using nonce.
	DecryptSegment(segment, nonce []byte) ([]byte, error)
}

// This is a slightly more general API of SegmentDecrypter that is more efficient because
// it requires less memory allocations. It is currently not a stable API and is Tink internal.
type segmentDecrypterWithDst interface {
	// DecryptSegmentWithDst does the same as DecryptSegment, but will store the result in `dst` if
	// `cap(dst)` is large enough.
	//
	// An error will be returned if `len(dst)` is not 0.
	DecryptSegmentWithDst(dst, segment, nonce []byte) ([]byte, error)
}

// Reader facilitates the decryption of ciphertexts created using a Writer.
//
// The scheme used for decrypting segments is specified by providing a
// SegmentDecrypter implementation. The implementation must align
// with the SegmentEncrypter used in the Writer.
type Reader struct {
	r                            io.Reader
	segmentDecrypter             SegmentDecrypter
	segmentDecrypterWithDst      segmentDecrypterWithDst
	useSegmentDecrypterWithDst   bool
	decryptedSegmentCnt          uint64
	firstCiphertextSegmentOffset int
	nonceSize                    int
	noncePrefix                  []byte
	plaintext                    []byte
	plaintextPos                 int
	ciphertext                   []byte
	ciphertextPos                int
	lastSegmentDecrypted         bool
	// ciphertextBufferLimit is the full segment buffer size
	// (CiphertextSegmentSize + 1 lookahead byte). r.ciphertext starts small
	// and grows toward this limit only if bytes actually arrive.
	ciphertextBufferLimit int
}

// ReaderParams contains the options for instantiating a Reader via NewReader().
type ReaderParams struct {
	// R is the underlying reader being wrapped.
	R io.Reader

	// SegmentDecrypter provides a method for decrypting segments.
	SegmentDecrypter SegmentDecrypter

	// NonceSize is the length of generated nonces. It must match the NonceSize
	// of the Writer used to create the ciphertext.
	NonceSize int

	// NoncePrefix is a constant that all nonces throughout the ciphertext start
	// with. It's extracted from the header of the ciphertext.
	NoncePrefix []byte

	// The size of the ciphertext segments.
	CiphertextSegmentSize int

	// FirstCiphertexSegmentOffset indicates where the ciphertext actually begins
	// in R. This allows for the existence of overhead in the stream unrelated to
	// this encryption scheme.
	FirstCiphertextSegmentOffset int
}

// NewReader creates a new Reader instance.
func NewReader(params ReaderParams) (*Reader, error) {
	if params.NonceSize-len(params.NoncePrefix) < 5 {
		return nil, ErrNonceSizeTooShort
	}

	// If params.SegmentDecrypter implements DecryptSegmentWithDst, then we use that because it is more efficient.
	decrypterWithDst, useDecrypterWithDst := params.SegmentDecrypter.(segmentDecrypterWithDst)

	return &Reader{
		r:                            params.R,
		segmentDecrypter:             params.SegmentDecrypter,
		segmentDecrypterWithDst:      decrypterWithDst,
		useSegmentDecrypterWithDst:   useDecrypterWithDst,
		nonceSize:                    params.NonceSize,
		noncePrefix:                  params.NoncePrefix,
		firstCiphertextSegmentOffset: params.FirstCiphertextSegmentOffset,

		// The buffer must be able to hold a full segment plus an extra byte
		// to detect the last segment, but is allocated small and grown as
		// bytes actually arrive, so that plaintexts much smaller than the
		// segment size do not pay for a full segment-sized allocation.
		ciphertext:            make([]byte, initialSegmentBufferSize(params.CiphertextSegmentSize+1)),
		ciphertextBufferLimit: params.CiphertextSegmentSize + 1,
	}, nil
}

// Read decrypts data from underlying reader and passes it to p.
func (r *Reader) Read(p []byte) (int, error) {
	if r.plaintextPos < len(r.plaintext) {
		n := copy(p, r.plaintext[r.plaintextPos:])
		r.plaintextPos += n
		return n, nil
	}
	if r.lastSegmentDecrypted {
		return 0, io.EOF
	}

	r.plaintext = r.plaintext[:0]
	r.plaintextPos = 0

	ctLim := r.ciphertextBufferLimit
	if r.decryptedSegmentCnt == 0 {
		ctLim -= r.firstCiphertextSegmentOffset
		if ctLim > r.ciphertextBufferLimit {
			// A negative FirstCiphertextSegmentOffset would require reading
			// more bytes than the segment buffer can hold. The keyset-based
			// streamingaead API never constructs such a Reader, but the
			// exported subtle constructors only bound the offset from above.
			return 0, ErrCiphertextSegmentTooShort
		}
	}
	n, err := r.readSegmentGrowing(ctLim)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return 0, err
	}

	var (
		lastSegment bool
		segment     int
	)
	if err != nil {
		lastSegment = true
		r.lastSegmentDecrypted = true
		segment = r.ciphertextPos + n
	} else {
		segment = r.ciphertextPos + n - 1
	}

	if segment < 0 {
		return 0, ErrCiphertextSegmentTooShort
	}

	nonce, err := generateSegmentNonce(r.nonceSize, r.noncePrefix, r.decryptedSegmentCnt, lastSegment)
	if err != nil {
		return 0, err
	}
	if r.useSegmentDecrypterWithDst {
		r.plaintext, err = r.segmentDecrypterWithDst.DecryptSegmentWithDst(r.plaintext[:0], r.ciphertext[:segment], nonce)
	} else {
		r.plaintext, err = r.segmentDecrypter.DecryptSegment(r.ciphertext[:segment], nonce)
	}
	if err != nil {
		return 0, err
	}

	// Copy 1 byte remainder to the beginning of ciphertext.
	if !lastSegment {
		remainderOffset := segment
		r.ciphertext[0] = r.ciphertext[remainderOffset]
		r.ciphertextPos = 1
	}

	r.decryptedSegmentCnt++

	n = copy(p, r.plaintext)
	r.plaintextPos = n
	return n, nil
}

// readSegmentGrowing reads into r.ciphertext[r.ciphertextPos:ctLim], growing
// r.ciphertext toward the full segment buffer size as the stream proves to
// have more data than the current buffer. ctLim must not exceed
// r.ciphertextBufferLimit; Read guarantees this. It is semantically identical
// to
//
//	io.ReadFull(r.r, r.ciphertext[r.ciphertextPos:ctLim])
//
// with a fully pre-allocated buffer: it returns the number of bytes read,
// io.EOF if no bytes were read, and io.ErrUnexpectedEOF if the stream ended
// after some bytes but before ctLim was reached.
//
// Throughout, end is the index one past the last buffered ciphertext byte,
// and each read fills r.ciphertext[end:] up to ctLim or the current buffer
// size, whichever is smaller. The loop and the error classification
// otherwise mirror io.ReadAtLeast.
func (r *Reader) readSegmentGrowing(ctLim int) (int, error) {
	start := r.ciphertextPos
	end := start
	var err error
	for end < ctLim && err == nil {
		if end == len(r.ciphertext) {
			// The buffer is full but the segment is not complete: grow
			// toward the full segment buffer size. Unlike the Writer, the
			// Reader never knows how much data is still pending.
			grown := make([]byte, grownSegmentBufferSize(len(r.ciphertext), 0, r.ciphertextBufferLimit))
			copy(grown, r.ciphertext[:end])
			r.ciphertext = grown
		}
		readLim := min(len(r.ciphertext), ctLim)
		var m int
		m, err = r.r.Read(r.ciphertext[end:readLim])
		end += m
	}
	if end >= ctLim {
		err = nil
	} else if end > start && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return end - start, err
}

// initialSegmentBufferSize returns the initial allocation size for a segment
// buffer: small, unless the full segment buffer is smaller still.
func initialSegmentBufferSize(limit int) int {
	const initial = 4096
	if limit < initial {
		return limit
	}
	return initial
}

// grownSegmentBufferSize returns the next size for a segment buffer of size
// cur that must grow toward limit: cur multiplied by the growth factor, but
// no smaller than needed, and limit itself once the chosen size would reach
// at least three quarters of it. needed is the number of buffered and
// pending bytes already known to the caller, or zero when unknown: a caller
// holding more data than a growth step covers allocates for that data in one
// step instead of paying for the intermediate steps. The large factor and
// the final jump bound the number of reallocations and the memory traffic of
// growth for segment-sized streams, and the jump also prevents a
// nearly-full-sized step, such as one covering all but the Reader's one-byte
// lookahead. The thresholds are arranged so that the multiplication cannot
// overflow: it is taken only when the result is below three quarters of
// limit.
func grownSegmentBufferSize(cur, needed, limit int) int {
	const growthFactor = 8
	jumpThreshold := limit - limit/4
	newSize := limit
	if cur < jumpThreshold/growthFactor {
		newSize = cur * growthFactor
	}
	if needed > newSize {
		newSize = needed
	}
	if newSize >= jumpThreshold {
		newSize = limit
	}
	return newSize
}

// generateSegmentNonce returns a nonce for a segment.
//
// The format of the nonce is:
//
//	nonce_prefix || ctr || last_block.
//
// nonce_prefix is a constant prefix used throughout the whole ciphertext.
//
// The ctr is a 32 bit counter.
//
// last_block is 1 byte which is set to 1 for the last segment and 0
// otherwise.
func generateSegmentNonce(size int, prefix []byte, segmentNum uint64, last bool) ([]byte, error) {
	if segmentNum >= math.MaxUint32 {
		return nil, ErrTooManySegments
	}

	nonce := make([]byte, size)
	copy(nonce, prefix)
	offset := len(prefix)
	binary.BigEndian.PutUint32(nonce[offset:], uint32(segmentNum))
	offset += 4
	if last {
		nonce[offset] = 1
	}
	return nonce, nil
}
