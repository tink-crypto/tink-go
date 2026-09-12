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

package noncebased_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle/noncebased"
)

func TestNonceBased(t *testing.T) {

	testcases := []struct {
		name                         string
		plaintextSize                int
		nonceSize                    int
		noncePrefixSize              int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		chunkSize                    int
	}{
		{
			name:                         "plaintextSizeAlignedWithSegmentSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "plaintextSizeNotAlignedWithSegmentSize",
			plaintextSize:                110,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "singleSegment",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         100,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "shortPlaintext",
			plaintextSize:                1,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         100,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "shortSegmentSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         10,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
		},
		{
			name:                         "largeChunkSize",
			plaintextSize:                100,
			nonceSize:                    10,
			noncePrefixSize:              5,
			plaintextSegmentSize:         10,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    500,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			writerParams := noncebased.WriterParams{
				NonceSize:                    tc.nonceSize,
				PlaintextSegmentSize:         tc.plaintextSegmentSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			plaintext, ciphertext, noncePrefix, err := testEncrypt(tc.plaintextSize, tc.noncePrefixSize, writerParams)
			if err != nil {
				t.Fatalf("encrypting failed: %v\n", err)
			}

			readerParams := noncebased.ReaderParams{
				NonceSize:                    tc.nonceSize,
				NoncePrefix:                  noncePrefix,
				CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			if err := testDecrypt(plaintext, ciphertext, tc.chunkSize, readerParams); err != nil {
				t.Fatalf("decrypting failed: %v\n", err)
			}
		})
	}
}

func TestNonceBased_doubleEncrypt(t *testing.T) {
	var (
		nonceSize                    = 10
		noncePrefixSize              = 5
		plaintextSegmentSize         = 20
		firstCiphertextSegmentOffset = 10
	)

	plaintext := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04, 0x05}, 20)

	noncePrefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(noncePrefix); err != nil {
		t.Fatalf("rand.Read() = _, err = %v, want nil", err)
	}

	var b bytes.Buffer
	w1, err := noncebased.NewWriter(noncebased.WriterParams{
		W:                            &b,
		SegmentEncrypter:             testEncrypterWithDst{},
		NoncePrefix:                  noncePrefix,
		NonceSize:                    nonceSize,
		PlaintextSegmentSize:         plaintextSegmentSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("noncebased.NewWriter() = _, err = %v, want nil", err)
	}

	w1.Write(plaintext)
	w1.Close()

	ciphertext1 := make([]byte, len(b.Bytes()))
	copy(ciphertext1, b.Bytes())
	b.Reset()

	w2, err := noncebased.NewWriter(noncebased.WriterParams{
		W:                            &b,
		SegmentEncrypter:             testEncrypterWithDst{},
		NoncePrefix:                  noncePrefix,
		NonceSize:                    nonceSize,
		PlaintextSegmentSize:         plaintextSegmentSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("noncebased.NewWriter = _, err = %v, want nil", err)
	}

	w2.Write(ciphertext1)
	w2.Close()

	ciphertext2 := make([]byte, len(b.Bytes()))
	copy(ciphertext2, b.Bytes())
	b.Reset()

	r2, err := noncebased.NewReader(noncebased.ReaderParams{
		R:                            bytes.NewReader(ciphertext2),
		SegmentDecrypter:             testDecrypterWithDst{},
		NonceSize:                    nonceSize,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        plaintextSegmentSize + nonceSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("noncebased.NewReader() = _, err = %v, want nil", err)
	}
	r1, err := noncebased.NewReader(noncebased.ReaderParams{
		R:                            r2,
		SegmentDecrypter:             testDecrypterWithDst{},
		NonceSize:                    nonceSize,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        plaintextSegmentSize + nonceSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("noncebased.NewReader() = _, err = %v, want nil", err)
	}

	decrypted, err := io.ReadAll(r1)
	if err != nil {
		t.Fatalf("io.ReadAll(r1) = _, err = %v, want nil", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decryption does not equal plaintext. (got = %x, want = %x)", decrypted, plaintext)
	}
}

func TestNonceBased_invalidParameters(t *testing.T) {

	testcases := []struct {
		name                         string
		plaintextSize                int
		nonceSize                    int
		noncePrefixSize              int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		chunkSize                    int
		expectedError                error
	}{
		{
			name:                         "nonceTooSmall",
			plaintextSize:                100,
			nonceSize:                    5,
			noncePrefixSize:              5,
			plaintextSegmentSize:         20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    5,
			expectedError:                noncebased.ErrNonceSizeTooShort,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			writerParams := noncebased.WriterParams{
				NonceSize:                    tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			_, _, _, err := testEncrypt(tc.plaintextSize, tc.noncePrefixSize, writerParams)
			if err != tc.expectedError {
				t.Errorf("did not produce expected error: got: %q, want: %q\n", err, tc.expectedError)
			}

			// Prepare empty input for testDecrypt().
			ciphertextSegmentSize := tc.plaintextSegmentSize + tc.nonceSize

			ciphertextSize := tc.firstCiphertextSegmentOffset
			ciphertextSize += (tc.plaintextSize / tc.plaintextSegmentSize) * ciphertextSegmentSize
			plaintextRemainder := tc.plaintextSize % tc.plaintextSegmentSize
			if plaintextRemainder > 0 {
				ciphertextSize += plaintextRemainder + tc.nonceSize
			}

			readerParams := noncebased.ReaderParams{
				NonceSize:                    tc.nonceSize,
				NoncePrefix:                  make([]byte, tc.noncePrefixSize),
				CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			if err := testDecrypt(make([]byte, tc.plaintextSize), make([]byte, ciphertextSize), tc.chunkSize, readerParams); err != tc.expectedError {
				t.Errorf("did not produce expected error: got: %q, want: %q\n", err, tc.expectedError)
			}
		})
	}
}

// testEncrypter is essentially a no-op cipher.
//
// It produces ciphertexts which contain the plaintext broken into segments,
// with the unmodified per-segment nonce placed at the end of each segment.
type testEncrypter struct {
}

func (e testEncrypter) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	ctLen := len(segment) + len(nonce)
	ciphertext := make([]byte, ctLen)
	copy(ciphertext, segment)
	copy(ciphertext[len(segment):], nonce)
	return ciphertext, nil
}

type testDecrypter struct {
}

func (d testDecrypter) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	tagStart := len(segment) - len(nonce)
	if tagStart < 0 {
		return nil, errors.New("segment too short")
	}
	tag := segment[tagStart:]
	if !bytes.Equal(nonce, tag) {
		return nil, fmt.Errorf("tag mismtach:\nsegment: %s\nnonce: %s\ntag: %s", hex.EncodeToString(segment), hex.EncodeToString(nonce), hex.EncodeToString(tag))
	}
	result := make([]byte, tagStart)
	copy(result, segment[:tagStart])
	return result, nil
}

// testEncrypterWithDst does the same as testEncrypter, but only implements the
// new EncryptSegmentWithDst function, and leave the old EncryptSegment function unimplemented.
type testEncrypterWithDst struct {
}

func (e testEncrypterWithDst) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (e testEncrypterWithDst) EncryptSegmentWithDst(dst, segment, nonce []byte) ([]byte, error) {
	if len(dst) != 0 {
		return nil, errors.New("dst must be empty")
	}
	ctLen := len(segment) + len(nonce)
	var ciphertext []byte
	if cap(dst) < ctLen {
		ciphertext = make([]byte, ctLen)
	} else {
		ciphertext = dst[:ctLen]
	}
	copy(ciphertext, segment)
	copy(ciphertext[len(segment):], nonce)
	return ciphertext, nil
}

type testDecrypterWithDst struct {
}

func (d testDecrypterWithDst) DecryptSegment(segment, nonce []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (d testDecrypterWithDst) DecryptSegmentWithDst(dst, segment, nonce []byte) ([]byte, error) {
	if len(dst) != 0 {
		return nil, errors.New("dst must be empty")
	}
	plaintextLen := len(segment) - len(nonce)
	if plaintextLen < 0 {
		return nil, errors.New("segment too short")
	}
	tag := segment[plaintextLen:]
	if !bytes.Equal(nonce, tag) {
		return nil, fmt.Errorf("tag mismtach:\nsegment: %s\nnonce: %s\ntag: %s", hex.EncodeToString(segment), hex.EncodeToString(nonce), hex.EncodeToString(tag))
	}
	var result []byte
	if cap(dst) < plaintextLen {
		result = make([]byte, plaintextLen)
	} else {
		result = dst[:plaintextLen]
	}
	copy(result, segment[:plaintextLen])
	return result, nil
}

// testEncrypt generates a random plaintext and random noncePrefix, then uses
// them to instantiate a noncebased.Writer and uses it to produce a ciphertext.
//
// The plaintext, ciphertext and nonce prefix are returned.
func testEncrypt(plaintextSize, noncePrefixSize int, wp noncebased.WriterParams) ([]byte, []byte, []byte, error) {
	var dst bytes.Buffer
	dstWriter := bufio.NewWriter(&dst)

	noncePrefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(noncePrefix); err != nil {
		return nil, nil, nil, err
	}

	wp.W = dstWriter
	wp.SegmentEncrypter = testEncrypterWithDst{}
	wp.NoncePrefix = noncePrefix

	w, err := noncebased.NewWriter(wp)
	if err != nil {
		return nil, nil, nil, err
	}

	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, nil, err
	}

	w.Write(plaintext)
	w.Close()
	dstWriter.Flush()
	ciphertext := dst.Bytes()

	return plaintext, ciphertext, noncePrefix, nil
}

// testDecrypt instantiates a noncebased.Reader, uses it to decrypt ciphertext
// and verifies it matches plaintext. While decrypting, it reads in chunkSize
// increments.
func testDecrypt(plaintext, ciphertext []byte, chunkSize int, rp noncebased.ReaderParams) error {
	rp.R = bytes.NewReader(ciphertext)
	rp.SegmentDecrypter = testDecrypterWithDst{}
	r, err := noncebased.NewReader(rp)
	if err != nil {
		return err
	}

	var (
		chunk     = make([]byte, chunkSize)
		decrypted = 0
		eof       = false
	)
	for !eof {
		n, err := r.Read(chunk)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading chunk: %v", err)
		}
		eof = err == io.EOF
		got := chunk[:n]
		want := plaintext[decrypted : decrypted+n]
		if !bytes.Equal(got, want) {
			return fmt.Errorf("decrypted data does not match. Got=%s;want=%s", hex.EncodeToString(got), hex.EncodeToString(want))
		}
		decrypted += n
	}
	if decrypted != len(plaintext) {
		return fmt.Errorf("number of decrypted bytes does not match. Got=%d,want=%d", decrypted, len(plaintext))
	}
	return nil
}

// This test uses testDecrypter and testEncrypter, to make sure that the old API is still working.
func TestEncryptDecryptWithOldInterface(t *testing.T) {
	plaintextSize := 110
	nonceSize := 10
	noncePrefixSize := 5
	plaintextSegmentSize := 20
	firstCiphertextSegmentOffset := 10
	chunkSize := 5

	noncePrefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(noncePrefix); err != nil {
		t.Fatalf("Generating nonce prefix failed: %v\n", err)
	}

	var dst bytes.Buffer
	dstWriter := bufio.NewWriter(&dst)

	writerParams := noncebased.WriterParams{
		NonceSize:                    nonceSize,
		PlaintextSegmentSize:         plaintextSegmentSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
		W:                            dstWriter,
		SegmentEncrypter:             testEncrypter{},
		NoncePrefix:                  noncePrefix,
	}

	w, err := noncebased.NewWriter(writerParams)
	if err != nil {
		t.Fatalf("Creating writer failed: %v\n", err)
	}

	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Generating plaintext failed: %v\n", err)
	}

	w.Write(plaintext)
	w.Close()
	dstWriter.Flush()
	ciphertext := dst.Bytes()

	readerParams := noncebased.ReaderParams{
		NonceSize:                    nonceSize,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        plaintextSegmentSize + nonceSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
		R:                            bytes.NewReader(ciphertext),
		SegmentDecrypter:             testDecrypterWithDst{},
	}

	r, err := noncebased.NewReader(readerParams)
	if err != nil {
		t.Fatalf("creating reader failed: %v\n", err)
	}

	var (
		chunk     = make([]byte, chunkSize)
		decrypted = 0
		eof       = false
	)
	for !eof {
		n, err := r.Read(chunk)
		if err != nil && err != io.EOF {
			t.Fatalf("Error reading chunk: %v", err)
		}
		eof = err == io.EOF
		got := chunk[:n]
		want := plaintext[decrypted : decrypted+n]
		if !bytes.Equal(got, want) {
			t.Fatalf("Decrypted data does not match. Got=%s;want=%s", hex.EncodeToString(got), hex.EncodeToString(want))
		}
		decrypted += n
	}
	if decrypted != len(plaintext) {
		t.Fatalf("Number of decrypted bytes does not match. Got=%d,want=%d", decrypted, len(plaintext))
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	var (
		nonceSize                    = 10
		noncePrefixSize              = 5
		plaintextSegmentSize         = 20
		firstCiphertextSegmentOffset = 10
		plaintextSize                = 100
	)

	writerParams := noncebased.WriterParams{
		NonceSize:                    nonceSize,
		PlaintextSegmentSize:         plaintextSegmentSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
	}

	_, ciphertext, noncePrefix, err := testEncrypt(plaintextSize, noncePrefixSize, writerParams)
	if err != nil {
		t.Fatalf("testEncrypt failed: %v", err)
	}

	readerParams := noncebased.ReaderParams{
		NonceSize:                    nonceSize,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        plaintextSegmentSize + nonceSize,
		FirstCiphertextSegmentOffset: firstCiphertextSegmentOffset,
		SegmentDecrypter:             testDecrypterWithDst{},
	}

	// Test all possible truncation lengths of the ciphertext stream.
	// Any truncated stream must produce an error upon reading.
	for i := 0; i < len(ciphertext); i++ {
		rp := readerParams
		rp.R = bytes.NewReader(ciphertext[:i])

		r, err := noncebased.NewReader(rp)
		if err != nil {
			t.Fatalf("noncebased.NewReader() failed: %v", err)
		}

		got, err := io.ReadAll(r)
		if err == nil {
			t.Errorf("io.ReadAll on ciphertext truncated at %d/%d bytes returned nil error; decrypted %d bytes of plaintext: %x (want error)",
				i, len(ciphertext), len(got), got)
		}
	}
}

// TestReadWithSmallInitialBuffer exercises the lazily-allocated ciphertext
// buffer in Reader. The buffer starts at a small initial size and grows
// toward CiphertextSegmentSize+1 as segments prove larger than the current
// allocation, so the interesting boundaries are ciphertext sizes and
// ciphertext segment sizes just below, at, and just above the initial buffer
// size (4096 bytes), and a segment large enough to walk the whole growth
// sequence up to the jump to the full buffer size, including their
// interaction with last-segment detection, the first-segment offset, and
// readers that return data in small chunks.
func TestReadWithSmallInitialBuffer(t *testing.T) {
	// initialBufferSize must match initialSegmentBufferSize() in
	// noncebased.go. The tests below probe ciphertext sizes around this
	// boundary; if the constant changes, they still pass but no longer pin
	// the boundary itself.
	const initialBufferSize = 4096

	const (
		nonceSize       = 10
		noncePrefixSize = 5
	)
	// With the test SegmentEncrypter a ciphertext segment is its plaintext
	// segment plus nonceSize trailing bytes, so a single-segment ciphertext
	// of size S corresponds to a plaintext of size S-nonceSize.
	testcases := []struct {
		name                         string
		plaintextSize                int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		chunkSize                    int
		oneByteReads                 bool
		dataErrReads                 bool
	}{
		{
			name:                 "singleSegmentCiphertextJustBelowInitialBuffer",
			plaintextSize:        initialBufferSize - nonceSize - 1, // ciphertext: 4095 bytes
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			name:                 "singleSegmentCiphertextExactlyInitialBuffer",
			plaintextSize:        initialBufferSize - nonceSize, // ciphertext: 4096 bytes
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			name:                 "singleSegmentCiphertextJustAboveInitialBuffer",
			plaintextSize:        initialBufferSize - nonceSize + 1, // ciphertext: 4097 bytes
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			name:                 "singleSegmentCiphertextWellAboveInitialBuffer",
			plaintextSize:        100000,
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			name:                 "emptyPlaintextLargeSegmentSize",
			plaintextSize:        0,
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			// Ciphertext segments of exactly initialBufferSize-1: the buffer
			// limit equals the initial size, so the buffer never grows and
			// every non-final segment fills it completely.
			name:                 "multiSegmentCiphertextSegmentJustBelowInitialBuffer",
			plaintextSize:        3*(initialBufferSize-nonceSize-1) + 100,
			plaintextSegmentSize: initialBufferSize - nonceSize - 1,
			chunkSize:            1000,
		},
		{
			// Ciphertext segments of exactly initialBufferSize: the buffer
			// limit is initialBufferSize+1, so the very first segment grows
			// the buffer by a single byte.
			name:                 "multiSegmentCiphertextSegmentExactlyInitialBuffer",
			plaintextSize:        3*(initialBufferSize-nonceSize) + 100,
			plaintextSegmentSize: initialBufferSize - nonceSize,
			chunkSize:            1000,
		},
		{
			name:                 "multiSegmentCiphertextSegmentJustAboveInitialBuffer",
			plaintextSize:        3*(initialBufferSize-nonceSize+1) + 100,
			plaintextSegmentSize: initialBufferSize - nonceSize + 1,
			chunkSize:            1000,
		},
		{
			// A segment large enough that the buffer walks the whole growth
			// sequence, ending with the jump to the full buffer size, and
			// then completes segments in the fully-grown buffer.
			name:                 "multiSegmentRequiringMultipleGrowthSteps",
			plaintextSize:        1<<20 + 100,
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
		},
		{
			// A plaintext that ends exactly at a segment boundary, so the
			// last ciphertext segment is a full-sized segment.
			name:                 "multiSegmentPlaintextAlignedWithSegmentSize",
			plaintextSize:        2 * (initialBufferSize - nonceSize),
			plaintextSegmentSize: initialBufferSize - nonceSize,
			chunkSize:            1000,
		},
		{
			name:                         "firstSegmentOffsetWithCiphertextAtInitialBuffer",
			plaintextSize:                initialBufferSize - nonceSize,
			plaintextSegmentSize:         1 << 20,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    1000,
		},
		{
			name:                         "firstSegmentOffsetWithMultipleSegmentsAtInitialBuffer",
			plaintextSize:                3*(initialBufferSize-nonceSize) + 100,
			plaintextSegmentSize:         initialBufferSize - nonceSize,
			firstCiphertextSegmentOffset: 10,
			chunkSize:                    1000,
		},
		{
			name:                 "oneByteReadsAcrossGrowBoundary",
			plaintextSize:        initialBufferSize - nonceSize + 1,
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
			oneByteReads:         true,
		},
		{
			name:                 "oneByteReadsMultiSegment",
			plaintextSize:        3*(initialBufferSize-nonceSize) + 100,
			plaintextSegmentSize: initialBufferSize - nonceSize,
			chunkSize:            7,
			oneByteReads:         true,
		},
		{
			// A reader that returns the final bytes together with io.EOF in
			// a single call, at a ciphertext size where the final read ends
			// mid-buffer.
			name:                 "dataWithEOFAcrossGrowBoundary",
			plaintextSize:        initialBufferSize - nonceSize + 1, // ciphertext: 4097 bytes
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
			dataErrReads:         true,
		},
		{
			// A reader that returns the final bytes together with io.EOF in
			// a single call, at a ciphertext size where the final read ends
			// exactly at a buffer boundary.
			name:                 "dataWithEOFAtBufferBoundary",
			plaintextSize:        initialBufferSize - nonceSize, // ciphertext: 4096 bytes
			plaintextSegmentSize: 1 << 20,
			chunkSize:            1000,
			dataErrReads:         true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			writerParams := noncebased.WriterParams{
				NonceSize:                    nonceSize,
				PlaintextSegmentSize:         tc.plaintextSegmentSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			plaintext, ciphertext, noncePrefix, err := testEncrypt(tc.plaintextSize, noncePrefixSize, writerParams)
			if err != nil {
				t.Fatalf("encrypting failed: %v", err)
			}

			var r io.Reader = bytes.NewReader(ciphertext)
			if tc.oneByteReads {
				r = iotest.OneByteReader(r)
			}
			if tc.dataErrReads {
				r = iotest.DataErrReader(r)
			}
			reader, err := noncebased.NewReader(noncebased.ReaderParams{
				R:                            r,
				SegmentDecrypter:             testDecrypterWithDst{},
				NonceSize:                    nonceSize,
				NoncePrefix:                  noncePrefix,
				CiphertextSegmentSize:        tc.plaintextSegmentSize + nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			})
			if err != nil {
				t.Fatalf("noncebased.NewReader() = _, err = %v, want nil", err)
			}

			var decrypted bytes.Buffer
			chunk := make([]byte, tc.chunkSize)
			for {
				n, err := reader.Read(chunk)
				decrypted.Write(chunk[:n])
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("reader.Read() = _, err = %v, want nil", err)
				}
			}
			if !bytes.Equal(decrypted.Bytes(), plaintext) {
				t.Fatalf("decrypted data does not match plaintext. Got %d bytes, want %d bytes", decrypted.Len(), len(plaintext))
			}
		})
	}
}

// TestReadTruncatedCiphertext pins Reader behavior for ciphertexts truncated
// at boundaries around the initial buffer size: every case must behave
// exactly as it did with the fully pre-allocated buffer.
func TestReadTruncatedCiphertext(t *testing.T) {
	const (
		nonceSize       = 10
		noncePrefixSize = 5
	)
	plaintextSegmentSize := 4096 - nonceSize
	writerParams := noncebased.WriterParams{
		NonceSize:            nonceSize,
		PlaintextSegmentSize: plaintextSegmentSize,
	}
	_, ciphertext, noncePrefix, err := testEncrypt(3*plaintextSegmentSize+100, noncePrefixSize, writerParams)
	if err != nil {
		t.Fatalf("encrypting failed: %v", err)
	}

	testcases := []struct {
		truncate     int
		dataErrReads bool
		wantErr      bool
	}{
		{truncate: 1, wantErr: true},
		{truncate: 4095, wantErr: true},
		{truncate: 4096, wantErr: true},
		// Truncating to exactly one full non-final segment plus its 1-byte
		// lookahead leaves that dangling byte to be decrypted as the final
		// segment, which fails authentication.
		{truncate: 4097, wantErr: true},
		// The same boundary with a reader that returns the final byte
		// together with io.EOF, so that the read which exactly fills the
		// segment buffer also reports the end of the stream.
		{truncate: 4097, dataErrReads: true, wantErr: true},
		{truncate: len(ciphertext) - 1, wantErr: true},
	}
	for _, tc := range testcases {
		name := fmt.Sprintf("truncatedAt%d", tc.truncate)
		if tc.dataErrReads {
			name += "DataErrReads"
		}
		t.Run(name, func(t *testing.T) {
			var r io.Reader = bytes.NewReader(ciphertext[:tc.truncate])
			if tc.dataErrReads {
				r = iotest.DataErrReader(r)
			}
			reader, err := noncebased.NewReader(noncebased.ReaderParams{
				R:                     r,
				SegmentDecrypter:      testDecrypterWithDst{},
				NonceSize:             nonceSize,
				NoncePrefix:           noncePrefix,
				CiphertextSegmentSize: plaintextSegmentSize + nonceSize,
			})
			if err != nil {
				t.Fatalf("noncebased.NewReader() = _, err = %v, want nil", err)
			}
			_, err = io.ReadAll(reader)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("io.ReadAll() = _, err = %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

// TestReadDegenerateFirstSegmentOffset verifies that a Reader constructed
// with a FirstCiphertextSegmentOffset outside [0, CiphertextSegmentSize+1]
// fails cleanly on the first Read. The keyset-based streamingaead API never
// produces such offsets, but the exported subtle constructors only bound the
// offset from above, so a negative offset can reach Read.
func TestReadDegenerateFirstSegmentOffset(t *testing.T) {
	const (
		nonceSize             = 10
		ciphertextSegmentSize = 100
	)
	for _, offset := range []int{-5, ciphertextSegmentSize + 2} {
		t.Run(fmt.Sprintf("offset%d", offset), func(t *testing.T) {
			reader, err := noncebased.NewReader(noncebased.ReaderParams{
				R:                            bytes.NewReader(make([]byte, 50)),
				SegmentDecrypter:             testDecrypterWithDst{},
				NonceSize:                    nonceSize,
				NoncePrefix:                  make([]byte, 5),
				CiphertextSegmentSize:        ciphertextSegmentSize,
				FirstCiphertextSegmentOffset: offset,
			})
			if err != nil {
				t.Fatalf("noncebased.NewReader() = _, err = %v, want nil", err)
			}
			if _, err := reader.Read(make([]byte, 10)); err != noncebased.ErrCiphertextSegmentTooShort {
				t.Fatalf("reader.Read() = _, err = %v, want ErrCiphertextSegmentTooShort", err)
			}
		})
	}
}

// TestWriteWithSmallInitialBuffer exercises the lazily-allocated plaintext
// buffer in Writer. The buffer starts at a small initial size and grows
// toward PlaintextSegmentSize as the written data proves larger than the
// current allocation, so the interesting boundaries are plaintext sizes and
// plaintext segment sizes just below, at, and just above the initial buffer
// size (4096 bytes), and a segment large enough to walk the whole growth
// sequence up to the jump to the full segment size, including their
// interaction with the first-segment offset and callers that write in small
// chunks. Each case additionally
// verifies that the produced ciphertext is byte-identical to one produced by
// a single Write call of the whole plaintext: the write pattern must not
// influence the output.
func TestWriteWithSmallInitialBuffer(t *testing.T) {
	// initialBufferSize must match initialSegmentBufferSize() in
	// noncebased.go. The tests below probe plaintext sizes around this
	// boundary; if the constant changes, they still pass but no longer pin
	// the boundary itself.
	const initialBufferSize = 4096

	const (
		nonceSize       = 10
		noncePrefixSize = 5
	)
	testcases := []struct {
		name                         string
		plaintextSize                int
		plaintextSegmentSize         int
		firstCiphertextSegmentOffset int
		writeChunkSize               int
	}{
		{
			name:                 "singleSegmentPlaintextJustBelowInitialBuffer",
			plaintextSize:        initialBufferSize - 1,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			name:                 "singleSegmentPlaintextExactlyInitialBuffer",
			plaintextSize:        initialBufferSize,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			name:                 "singleSegmentPlaintextJustAboveInitialBuffer",
			plaintextSize:        initialBufferSize + 1,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			name:                 "singleSegmentPlaintextWellAboveInitialBuffer",
			plaintextSize:        100000,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			name:                 "emptyPlaintextLargeSegmentSize",
			plaintextSize:        0,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			// Plaintext segments one byte below the initial buffer size: the
			// buffer limit is below the initial size, so the buffer starts at
			// the limit and never grows.
			name:                 "multiSegmentSegmentJustBelowInitialBuffer",
			plaintextSize:        3*(initialBufferSize-1) + 100,
			plaintextSegmentSize: initialBufferSize - 1,
			writeChunkSize:       1000,
		},
		{
			// Plaintext segments of exactly the initial buffer size: the
			// buffer starts at the full segment size and never grows.
			name:                 "multiSegmentSegmentExactlyInitialBuffer",
			plaintextSize:        3*initialBufferSize + 100,
			plaintextSegmentSize: initialBufferSize,
			writeChunkSize:       1000,
		},
		{
			// Plaintext segments one byte above the initial buffer size: the
			// very first segment grows the buffer by a single byte.
			name:                 "multiSegmentSegmentJustAboveInitialBuffer",
			plaintextSize:        3*(initialBufferSize+1) + 100,
			plaintextSegmentSize: initialBufferSize + 1,
			writeChunkSize:       1000,
		},
		{
			// A segment large enough that the buffer walks the whole growth
			// sequence, ending with the jump to the full segment size, and
			// then completes segments in the fully-grown buffer.
			name:                 "multiSegmentRequiringMultipleGrowthSteps",
			plaintextSize:        1<<20 + 100,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1000,
		},
		{
			// A first Write large enough that the buffer is sized to the
			// pending data exactly, followed by writes that grow it from
			// that intermediate size and complete segments.
			name:                 "largeFirstWriteThenGrowthFromOddSize",
			plaintextSize:        1<<20 + 100,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       500000,
		},
		{
			// A plaintext that ends exactly at a segment boundary: Write
			// defers the exactly-filled segment, and Close emits it as the
			// last segment.
			name:                 "multiSegmentPlaintextAlignedWithSegmentSize",
			plaintextSize:        2 * initialBufferSize,
			plaintextSegmentSize: initialBufferSize,
			writeChunkSize:       1000,
		},
		{
			// A single Write that fills the initial buffer exactly without
			// completing a segment, followed directly by Close.
			name:                 "singleWriteFillingInitialBufferThenClose",
			plaintextSize:        initialBufferSize,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       initialBufferSize,
		},
		{
			name:                         "firstSegmentOffsetWithPlaintextAtInitialBuffer",
			plaintextSize:                initialBufferSize,
			plaintextSegmentSize:         1 << 20,
			firstCiphertextSegmentOffset: 10,
			writeChunkSize:               1000,
		},
		{
			name:                         "firstSegmentOffsetWithMultipleSegmentsAtInitialBuffer",
			plaintextSize:                3*initialBufferSize + 100,
			plaintextSegmentSize:         initialBufferSize,
			firstCiphertextSegmentOffset: 10,
			writeChunkSize:               1000,
		},
		{
			name:                 "oneByteWritesAcrossGrowBoundary",
			plaintextSize:        initialBufferSize + 1,
			plaintextSegmentSize: 1 << 20,
			writeChunkSize:       1,
		},
		{
			name:                 "oneByteWritesMultiSegment",
			plaintextSize:        2*initialBufferSize + 50,
			plaintextSegmentSize: initialBufferSize,
			writeChunkSize:       1,
		},
	}

	encryptChunked := func(t *testing.T, plaintext, noncePrefix []byte, segmentSize, offset, chunkSize int) []byte {
		t.Helper()
		var buf bytes.Buffer
		w, err := noncebased.NewWriter(noncebased.WriterParams{
			W:                            &buf,
			SegmentEncrypter:             testEncrypterWithDst{},
			NonceSize:                    nonceSize,
			NoncePrefix:                  noncePrefix,
			PlaintextSegmentSize:         segmentSize,
			FirstCiphertextSegmentOffset: offset,
		})
		if err != nil {
			t.Fatalf("noncebased.NewWriter() = _, err = %v, want nil", err)
		}
		for pos := 0; pos < len(plaintext); {
			end := pos + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			n, err := w.Write(plaintext[pos:end])
			if err != nil {
				t.Fatalf("w.Write() = _, err = %v, want nil", err)
			}
			pos += n
		}
		if err := w.Close(); err != nil {
			t.Fatalf("w.Close() = err = %v, want nil", err)
		}
		return buf.Bytes()
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.plaintextSize)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand.Read() = _, err = %v, want nil", err)
			}
			noncePrefix := make([]byte, noncePrefixSize)
			if _, err := rand.Read(noncePrefix); err != nil {
				t.Fatalf("rand.Read() = _, err = %v, want nil", err)
			}

			ciphertext := encryptChunked(t, plaintext, noncePrefix, tc.plaintextSegmentSize, tc.firstCiphertextSegmentOffset, tc.writeChunkSize)
			singleWrite := encryptChunked(t, plaintext, noncePrefix, tc.plaintextSegmentSize, tc.firstCiphertextSegmentOffset, tc.plaintextSize+1)
			if !bytes.Equal(ciphertext, singleWrite) {
				t.Fatalf("chunked writes produced a different ciphertext than a single write. Got %d bytes, want %d bytes", len(ciphertext), len(singleWrite))
			}

			readerParams := noncebased.ReaderParams{
				NonceSize:                    nonceSize,
				NoncePrefix:                  noncePrefix,
				CiphertextSegmentSize:        tc.plaintextSegmentSize + nonceSize,
				FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
			}
			if err := testDecrypt(plaintext, ciphertext, 1000, readerParams); err != nil {
				t.Fatalf("decrypting failed: %v", err)
			}
		})
	}
}

// TestWriteDegenerateFirstSegmentOffset verifies that a Writer constructed
// with a FirstCiphertextSegmentOffset outside [0, PlaintextSegmentSize] fails
// cleanly on the first Write. The keyset-based streamingaead API never
// produces such offsets, but the exported subtle constructors only bound the
// offset from above, so a negative offset can reach Write.
func TestWriteDegenerateFirstSegmentOffset(t *testing.T) {
	const (
		nonceSize            = 10
		plaintextSegmentSize = 100
	)
	for _, offset := range []int{-5, plaintextSegmentSize + 1} {
		t.Run(fmt.Sprintf("offset%d", offset), func(t *testing.T) {
			w, err := noncebased.NewWriter(noncebased.WriterParams{
				W:                            &bytes.Buffer{},
				SegmentEncrypter:             testEncrypterWithDst{},
				NonceSize:                    nonceSize,
				NoncePrefix:                  make([]byte, 5),
				PlaintextSegmentSize:         plaintextSegmentSize,
				FirstCiphertextSegmentOffset: offset,
			})
			if err != nil {
				t.Fatalf("noncebased.NewWriter() = _, err = %v, want nil", err)
			}
			if _, err := w.Write(make([]byte, 50)); err == nil {
				t.Fatal("w.Write() = _, err = nil, want error")
			}
		})
	}
}
