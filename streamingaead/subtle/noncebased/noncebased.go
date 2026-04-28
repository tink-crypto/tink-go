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
	"sync/atomic"
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
	ciphertext                   []byte
	closed                       bool
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
		plaintext:                    make([]byte, params.PlaintextSegmentSize),
	}, nil
}

// Write encrypts passed data and passes the encrypted data to the underlying writer.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write on closed writer")
	}

	pos := 0
	for {
		ptLim := len(w.plaintext)
		if w.encryptedSegmentCnt == 0 {
			ptLim -= w.firstCiphertextSegmentOffset
		}
		n := copy(w.plaintext[w.plaintextPos:ptLim], p[pos:])
		w.plaintextPos += n
		pos += n
		if pos == len(p) {
			break
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

		// Allocate an extra byte to detect the last segment.
		ciphertext: make([]byte, params.CiphertextSegmentSize+1),
	}, nil
}

// Read decrypts data from underlying reader and passes it to p.
func (r *Reader) Read(p []byte) (int, error) {
	if r.plaintextPos < len(r.plaintext) {
		n := copy(p, r.plaintext[r.plaintextPos:])
		r.plaintextPos += n
		return n, nil
	}

	r.plaintext = r.plaintext[:0]
	r.plaintextPos = 0

	ctLim := len(r.ciphertext)
	if r.decryptedSegmentCnt == 0 {
		ctLim -= r.firstCiphertextSegmentOffset
	}
	n, err := io.ReadFull(r.r, r.ciphertext[r.ciphertextPos:ctLim])
	if err != nil && err != io.ErrUnexpectedEOF {
		return 0, err
	}

	var (
		lastSegment bool
		segment     int
	)
	if err != nil {
		lastSegment = true
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

// ReaderAt provides random-access decryption of ciphertexts created using a
// Writer.
//
// The scheme used for decrypting segments is specified by providing a
// SegmentDecrypter implementation. The implementation must align with the
// SegmentEncrypter used in the Writer.
//
// ReaderAt is safe for concurrent use; ReadAt calls execute in parallel. The
// most recently decrypted segment is cached as an immutable snapshot via an
// atomic pointer; concurrent reads of distinct segments may each decrypt and
// the cache retains whichever store completes last.
//
// The provided SegmentDecrypter must be safe for concurrent DecryptSegment
// calls.
type ReaderAt struct {
	r                            io.ReaderAt
	segmentDecrypter             SegmentDecrypter
	segmentDecrypterWithDst      segmentDecrypterWithDst
	useSegmentDecrypterWithDst   bool
	nonceSize                    int
	noncePrefix                  []byte
	ciphertextSegmentSize        int
	plaintextSegmentSize         int
	firstCiphertextSegmentOffset int
	tagSize                      int

	numberOfSegments          int64
	lastCiphertextSegmentSize int
	plaintextSize             int64

	// cache holds the most recently decrypted segment. A stored cachedSegment is
	// never mutated. This single-slot cache could be extended to a small LRU if
	// profiling indicates contention on repeated decryption of a working set
	// larger than one segment.
	cache atomic.Pointer[cachedSegment]
}

type cachedSegment struct {
	nr        int64
	plaintext []byte
}

// ReaderAtParams contains the options for instantiating a ReaderAt via
// NewReaderAt().
type ReaderAtParams struct {
	// R is the underlying ciphertext source. Offset 0 of R must correspond to
	// the first byte of segment_0, i.e. the position of the stream immediately
	// after the header has been consumed. This matches the semantics of
	// ReaderParams.R.
	R io.ReaderAt

	// CiphertextSize is the total number of segment ciphertext bytes available
	// via R (i.e. excluding the header).
	CiphertextSize int64

	// SegmentDecrypter provides a method for decrypting segments.
	SegmentDecrypter SegmentDecrypter

	// NonceSize is the length of generated nonces. It must match the NonceSize
	// of the Writer used to create the ciphertext.
	NonceSize int

	// NoncePrefix is a constant that all nonces throughout the ciphertext start
	// with. It's extracted from the header of the ciphertext.
	NoncePrefix []byte

	// CiphertextSegmentSize is the size of full ciphertext segments.
	CiphertextSegmentSize int

	// PlaintextSegmentSize is the size of full plaintext segments. It must equal
	// CiphertextSegmentSize minus the per-segment authentication tag overhead.
	PlaintextSegmentSize int

	// FirstCiphertextSegmentOffset determines how many bytes segment_0's
	// ciphertext is shortened by relative to CiphertextSegmentSize, accounting
	// for the stream header and any caller alignment offset. R must still begin
	// at the first byte of segment_0's ciphertext.
	FirstCiphertextSegmentOffset int
}

// NewReaderAt creates a new ReaderAt instance.
func NewReaderAt(params ReaderAtParams) (*ReaderAt, error) {
	if params.NonceSize-len(params.NoncePrefix) < 5 {
		return nil, ErrNonceSizeTooShort
	}
	tagSize := params.CiphertextSegmentSize - params.PlaintextSegmentSize
	if tagSize <= 0 {
		return nil, errors.New("ciphertext segment size must exceed plaintext segment size")
	}
	if params.FirstCiphertextSegmentOffset < 0 ||
		params.FirstCiphertextSegmentOffset+tagSize >= params.CiphertextSegmentSize {
		return nil, errors.New("invalid first ciphertext segment offset")
	}
	if params.CiphertextSize < int64(tagSize) {
		return nil, errors.New("ciphertext too short")
	}
	if params.CiphertextSize > math.MaxInt64-int64(params.FirstCiphertextSegmentOffset) {
		return nil, errors.New("ciphertext size too large")
	}

	streamSize := params.CiphertextSize + int64(params.FirstCiphertextSegmentOffset)
	fullSegments := streamSize / int64(params.CiphertextSegmentSize)
	remainder := streamSize % int64(params.CiphertextSegmentSize)
	var (
		numberOfSegments          int64
		lastCiphertextSegmentSize int
	)
	if remainder > 0 {
		numberOfSegments = fullSegments + 1
		if remainder < int64(tagSize) {
			return nil, errors.New("ciphertext too short")
		}
		lastCiphertextSegmentSize = int(remainder)
	} else {
		numberOfSegments = fullSegments
		lastCiphertextSegmentSize = params.CiphertextSegmentSize
	}
	if numberOfSegments > math.MaxUint32 {
		return nil, ErrTooManySegments
	}

	overhead := numberOfSegments * int64(tagSize)
	if overhead > params.CiphertextSize {
		return nil, errors.New("ciphertext too short")
	}
	plaintextSize := params.CiphertextSize - overhead

	decrypterWithDst, useDecrypterWithDst := params.SegmentDecrypter.(segmentDecrypterWithDst)

	return &ReaderAt{
		r:                            params.R,
		segmentDecrypter:             params.SegmentDecrypter,
		segmentDecrypterWithDst:      decrypterWithDst,
		useSegmentDecrypterWithDst:   useDecrypterWithDst,
		nonceSize:                    params.NonceSize,
		noncePrefix:                  params.NoncePrefix,
		ciphertextSegmentSize:        params.CiphertextSegmentSize,
		plaintextSegmentSize:         params.PlaintextSegmentSize,
		firstCiphertextSegmentOffset: params.FirstCiphertextSegmentOffset,
		tagSize:                      tagSize,
		numberOfSegments:             numberOfSegments,
		lastCiphertextSegmentSize:    lastCiphertextSegmentSize,
		plaintextSize:                plaintextSize,
	}, nil
}

// Size returns the size of the plaintext.
//
// The returned value is derived from the ciphertext size provided at
// construction time and is not authenticated until the final segment has been
// successfully decrypted.
func (r *ReaderAt) Size() int64 {
	return r.plaintextSize
}

// segmentNr returns the segment number containing the given plaintext offset.
func (r *ReaderAt) segmentNr(ptOff int64) int64 {
	return (ptOff + int64(r.firstCiphertextSegmentOffset)) / int64(r.plaintextSegmentSize)
}

// ciphertextSegmentBounds returns the offset and length within r.r of the
// ciphertext for the given segment number.
func (r *ReaderAt) ciphertextSegmentBounds(segmentNr int64) (off int64, length int) {
	length = r.ciphertextSegmentSize
	if segmentNr == r.numberOfSegments-1 {
		length = r.lastCiphertextSegmentSize
	}
	if segmentNr == 0 {
		return 0, length - r.firstCiphertextSegmentOffset
	}
	return segmentNr*int64(r.ciphertextSegmentSize) - int64(r.firstCiphertextSegmentOffset), length
}

// CiphertextRange returns the byte range [off, off+n) within the underlying
// ciphertext source that ReadAt will access in order to satisfy a plaintext
// read of [ptOff, ptOff+ptLen). Callers backed by remote storage can use this
// to prefetch the required bytes in a single round trip.
//
// The returned range covers whole ciphertext segments and does not include the
// stream header.
func (r *ReaderAt) CiphertextRange(ptOff, ptLen int64) (off, n int64) {
	if ptLen <= 0 || ptOff < 0 || ptOff >= r.plaintextSize {
		return 0, 0
	}
	end := ptOff + ptLen
	if end > r.plaintextSize {
		end = r.plaintextSize
	}
	firstOff, _ := r.ciphertextSegmentBounds(r.segmentNr(ptOff))
	lastOff, lastLen := r.ciphertextSegmentBounds(r.segmentNr(end - 1))
	return firstOff, lastOff + int64(lastLen) - firstOff
}

// loadSegment returns the decrypted plaintext of the given segment, using the
// atomic cache if it already holds segmentNr. On a cache miss the segment is
// fetched and decrypted into a fresh buffer which is then stored in the cache
// and returned; the returned slice is never subsequently mutated.
func (r *ReaderAt) loadSegment(segmentNr int64) ([]byte, error) {
	if cs := r.cache.Load(); cs != nil && cs.nr == segmentNr {
		return cs.plaintext, nil
	}
	ctOff, ctLen := r.ciphertextSegmentBounds(segmentNr)
	ct := make([]byte, ctLen)
	if _, err := readFullAt(r.r, ct, ctOff); err != nil {
		return nil, err
	}
	isLast := segmentNr == r.numberOfSegments-1
	nonce, err := generateSegmentNonce(r.nonceSize, r.noncePrefix, uint64(segmentNr), isLast)
	if err != nil {
		return nil, err
	}
	var pt []byte
	if r.useSegmentDecrypterWithDst {
		pt, err = r.segmentDecrypterWithDst.DecryptSegmentWithDst(nil, ct, nonce)
	} else {
		pt, err = r.segmentDecrypter.DecryptSegment(ct, nonce)
	}
	if err != nil {
		return nil, err
	}
	r.cache.Store(&cachedSegment{nr: segmentNr, plaintext: pt})
	return pt, nil
}

// ReadAt decrypts and returns plaintext bytes at the given offset. It
// implements io.ReaderAt.
func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	n := 0
	for n < len(p) && off < r.plaintextSize {
		segNr := r.segmentNr(off)
		var segOff int
		if segNr == 0 {
			segOff = int(off)
		} else {
			segOff = int((off + int64(r.firstCiphertextSegmentOffset)) % int64(r.plaintextSegmentSize))
		}
		pt, err := r.loadSegment(segNr)
		if err != nil {
			return n, err
		}
		c := copy(p[n:], pt[segOff:])
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readFullAt reads exactly len(buf) bytes from r at the given offset.
//
// The io.ReaderAt contract requires a non-nil error whenever n < len(buf), so a
// single call would normally suffice; this loops defensively to tolerate
// non-conforming implementations.
func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.ReadAt(buf[n:], off+int64(n))
		n += m
		if err != nil {
			if err == io.EOF && n == len(buf) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}
