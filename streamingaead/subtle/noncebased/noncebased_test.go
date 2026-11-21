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

// testNonceRecordingEncrypter does the same as testEncrypter, but also records
// every nonce it is called with.
type testNonceRecordingEncrypter struct {
	nonces *[][]byte
}

func (e testNonceRecordingEncrypter) EncryptSegment(segment, nonce []byte) ([]byte, error) {
	*e.nonces = append(*e.nonces, bytes.Clone(nonce))
	return testEncrypter{}.EncryptSegment(segment, nonce)
}

// testFailingWriter writes to buf. While fail is set, each Write stores only
// the first half of p and then returns errTestWrite.
type testFailingWriter struct {
	buf  bytes.Buffer
	fail bool
}

var errTestWrite = errors.New("test write error")

func (w *testFailingWriter) Write(p []byte) (int, error) {
	if w.fail {
		n, _ := w.buf.Write(p[:len(p)/2])
		return n, errTestWrite
	}
	return w.buf.Write(p)
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

func TestWriterErrorsAreSticky(t *testing.T) {
	var (
		nonceSize            = 10
		noncePrefixSize      = 5
		plaintextSegmentSize = 20
	)
	// The first segment holds plaintextSegmentSize bytes, so a Write of more
	// than that encrypts and writes a segment, while a shorter Write does not.
	short := bytes.Repeat([]byte{0x01}, plaintextSegmentSize/2)
	long := bytes.Repeat([]byte{0x02}, 2*plaintextSegmentSize)

	testcases := []struct {
		name string
		// failing is called while the underlying writer fails and must return
		// the error observed by the caller.
		failing func(t *testing.T, w *noncebased.Writer) error
		// after is called once the underlying writer works again and returns
		// the errors of all calls it makes.
		after func(w *noncebased.Writer) []error
	}{
		{
			name: "writeFailsThenWrite",
			failing: func(t *testing.T, w *noncebased.Writer) error {
				_, err := w.Write(long)
				return err
			},
			after: func(w *noncebased.Writer) []error {
				_, err1 := w.Write(long)
				err2 := w.Close()
				return []error{err1, err2}
			},
		},
		{
			name: "writeFailsThenClose",
			failing: func(t *testing.T, w *noncebased.Writer) error {
				_, err := w.Write(long)
				return err
			},
			after: func(w *noncebased.Writer) []error {
				return []error{w.Close()}
			},
		},
		{
			name: "closeFailsThenWrite",
			failing: func(t *testing.T, w *noncebased.Writer) error {
				if _, err := w.Write(short); err != nil {
					t.Fatalf("w.Write() err = %v, want nil", err)
				}
				return w.Close()
			},
			after: func(w *noncebased.Writer) []error {
				_, err1 := w.Write(short)
				err2 := w.Close()
				return []error{err1, err2}
			},
		},
		{
			name: "closeFailsThenClose",
			failing: func(t *testing.T, w *noncebased.Writer) error {
				if _, err := w.Write(short); err != nil {
					t.Fatalf("w.Write() err = %v, want nil", err)
				}
				return w.Close()
			},
			after: func(w *noncebased.Writer) []error {
				return []error{w.Close()}
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			noncePrefix := make([]byte, noncePrefixSize)
			if _, err := rand.Read(noncePrefix); err != nil {
				t.Fatalf("rand.Read() = _, err = %v, want nil", err)
			}
			var nonces [][]byte
			dst := &testFailingWriter{}
			w, err := noncebased.NewWriter(noncebased.WriterParams{
				W:                    dst,
				SegmentEncrypter:     testNonceRecordingEncrypter{nonces: &nonces},
				NoncePrefix:          noncePrefix,
				NonceSize:            nonceSize,
				PlaintextSegmentSize: plaintextSegmentSize,
			})
			if err != nil {
				t.Fatalf("noncebased.NewWriter() = _, err = %v, want nil", err)
			}

			dst.fail = true
			if err := tc.failing(t, w); !errors.Is(err, errTestWrite) {
				t.Fatalf("err = %v, want %v", err, errTestWrite)
			}
			dst.fail = false
			written := dst.buf.Len()

			for i, err := range tc.after(w) {
				if !errors.Is(err, errTestWrite) {
					t.Errorf("call %d after the failure: err = %v, want %v", i, err, errTestWrite)
				}
			}
			if got := dst.buf.Len(); got != written {
				t.Errorf("%d bytes written after the failure, want 0", got-written)
			}
			seen := make(map[string]bool)
			for _, nonce := range nonces {
				if seen[string(nonce)] {
					t.Errorf("nonce %x used more than once", nonce)
				}
				seen[string(nonce)] = true
			}
		})
	}
}

func TestWriterCloseAfterSuccessfulClose(t *testing.T) {
	noncePrefix := make([]byte, 5)
	if _, err := rand.Read(noncePrefix); err != nil {
		t.Fatalf("rand.Read() = _, err = %v, want nil", err)
	}
	var b bytes.Buffer
	w, err := noncebased.NewWriter(noncebased.WriterParams{
		W:                    &b,
		SegmentEncrypter:     testEncrypterWithDst{},
		NoncePrefix:          noncePrefix,
		NonceSize:            10,
		PlaintextSegmentSize: 20,
	})
	if err != nil {
		t.Fatalf("noncebased.NewWriter() = _, err = %v, want nil", err)
	}
	if _, err := w.Write([]byte("plaintext")); err != nil {
		t.Fatalf("w.Write() err = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("w.Close() err = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second w.Close() err = %v, want nil", err)
	}
	if _, err := w.Write([]byte("more")); err == nil {
		t.Errorf("w.Write() after w.Close() err = nil, want error")
	}
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
