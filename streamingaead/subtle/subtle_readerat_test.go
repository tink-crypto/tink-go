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

package subtle_test

import (
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle"
	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle/noncebased"
)

type readerAtCipher interface {
	NewEncryptingWriter(io.Writer, []byte) (io.WriteCloser, error)
	NewDecryptingReaderAt(io.ReaderAt, int64, []byte) (*noncebased.ReaderAt, error)
	HeaderLength() int
}

func newReaderAtCiphers(t *testing.T) map[string]readerAtCipher {
	t.Helper()
	gcm, err := subtle.NewAESGCMHKDF(ikm, "SHA256", 16, 256, 0)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF: %v", err)
	}
	gcmOffset, err := subtle.NewAESGCMHKDF(ikm, "SHA256", 16, 256, 8)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF: %v", err)
	}
	ctr, err := subtle.NewAESCTRHMAC(ikm, "SHA256", 16, "SHA256", 16, 256, 0)
	if err != nil {
		t.Fatalf("NewAESCTRHMAC: %v", err)
	}
	return map[string]readerAtCipher{
		"AESGCMHKDF":          gcm,
		"AESGCMHKDF-offset-8": gcmOffset,
		"AESCTRHMAC":          ctr,
	}
}

func TestNewDecryptingReaderAt(t *testing.T) {
	for name, cipher := range newReaderAtCiphers(t) {
		t.Run(name, func(t *testing.T) {
			for _, ptSize := range []int{0, 1, 200, 1000, 5000} {
				pt, ct, err := encryptReaderAt(cipher, ptSize)
				if err != nil {
					t.Fatalf("encrypt(%d): %v", ptSize, err)
				}
				r, err := cipher.NewDecryptingReaderAt(bytes.NewReader(ct), int64(len(ct)), aad)
				if err != nil {
					t.Fatalf("NewDecryptingReaderAt(%d): %v", ptSize, err)
				}
				if got, want := r.Size(), int64(ptSize); got != want {
					t.Errorf("Size() = %d, want %d", got, want)
				}
				got := make([]byte, ptSize)
				if n, err := r.ReadAt(got, 0); n != ptSize || (err != nil && err != io.EOF) {
					t.Fatalf("ReadAt(0) = %d, %v; want %d, nil", n, err, ptSize)
				}
				if !bytes.Equal(got, pt) {
					t.Errorf("plaintext mismatch (size %d)", ptSize)
				}
			}
		})
	}
}

func TestNewDecryptingReaderAtRandomOffsets(t *testing.T) {
	for name, cipher := range newReaderAtCiphers(t) {
		t.Run(name, func(t *testing.T) {
			pt, ct, err := encryptReaderAt(cipher, 8000)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			r, err := cipher.NewDecryptingReaderAt(bytes.NewReader(ct), int64(len(ct)), aad)
			if err != nil {
				t.Fatalf("NewDecryptingReaderAt: %v", err)
			}
			rng := rand.New(rand.NewSource(42))
			for i := 0; i < 200; i++ {
				off := rng.Int63n(int64(len(pt)))
				l := rng.Intn(400) + 1
				buf := make([]byte, l)
				n, err := r.ReadAt(buf, off)
				end := int(off) + l
				if end > len(pt) {
					end = len(pt)
				}
				if n != end-int(off) || !bytes.Equal(buf[:n], pt[off:end]) {
					t.Fatalf("iter %d: mismatch at off=%d (n=%d, err=%v)", i, off, n, err)
				}
			}
		})
	}
}

func TestNewDecryptingReaderAtBadAAD(t *testing.T) {
	for name, cipher := range newReaderAtCiphers(t) {
		t.Run(name, func(t *testing.T) {
			_, ct, err := encryptReaderAt(cipher, 500)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			r, err := cipher.NewDecryptingReaderAt(bytes.NewReader(ct), int64(len(ct)), []byte("wrong"))
			if err != nil {
				t.Fatalf("NewDecryptingReaderAt: %v", err)
			}
			buf := make([]byte, 10)
			if _, err := r.ReadAt(buf, 0); err == nil {
				t.Error("ReadAt with wrong AAD succeeded, want error")
			}
		})
	}
}

func TestNewDecryptingReaderAtTruncated(t *testing.T) {
	for name, cipher := range newReaderAtCiphers(t) {
		t.Run(name, func(t *testing.T) {
			_, ct, err := encryptReaderAt(cipher, 500)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if _, err := cipher.NewDecryptingReaderAt(bytes.NewReader(ct), 5, aad); err == nil {
				t.Error("NewDecryptingReaderAt with size < header succeeded, want error")
			}
			bad := make([]byte, len(ct))
			copy(bad, ct)
			bad[0] = 0
			if _, err := cipher.NewDecryptingReaderAt(bytes.NewReader(bad), int64(len(bad)), aad); err == nil {
				t.Error("NewDecryptingReaderAt with bad header byte succeeded, want error")
			}
		})
	}
}

// readerAtModifyCipher pairs a readerAtCipher with the segment geometry needed
// to compute segment boundaries for tamper tests.
type readerAtModifyCipher struct {
	name               string
	cipher             readerAtCipher
	segmentSize        int
	firstSegmentOffset int
}

func newReaderAtModifyCiphers(t *testing.T) []readerAtModifyCipher {
	t.Helper()
	gcm, err := subtle.NewAESGCMHKDF(ikm, "SHA256", 16, 256, 8)
	if err != nil {
		t.Fatalf("NewAESGCMHKDF: %v", err)
	}
	ctr, err := subtle.NewAESCTRHMAC(ikm, "SHA256", 16, "SHA256", 16, 256, 8)
	if err != nil {
		t.Fatalf("NewAESCTRHMAC: %v", err)
	}
	return []readerAtModifyCipher{
		{"AESGCMHKDF", gcm, 256, 8},
		{"AESCTRHMAC", ctr, 256, 8},
	}
}

// checkReaderAtDetectsTampering constructs a ReaderAt over a tampered
// ciphertext and asserts that reads at an exponential grid of (offset, length)
// positions either fail or return bytes identical to the original plaintext.
// It returns the number of grid positions at which an error was reported.
func checkReaderAtDetectsTampering(t *testing.T, c readerAtCipher, pt, tamperedCt []byte) int {
	t.Helper()
	r, err := c.NewDecryptingReaderAt(bytes.NewReader(tamperedCt), int64(len(tamperedCt)), aad)
	if err != nil {
		return 1
	}
	failures := 0
	for start := 0; start < len(pt); start = 2*start + 1 {
		for l := 1; l < len(pt); l *= 2 {
			buf := make([]byte, l)
			n, err := r.ReadAt(buf, int64(start))
			if err != nil && err != io.EOF {
				failures++
				continue
			}
			end := start + n
			if end > len(pt) {
				t.Fatalf("ReadAt(%d,%d) returned n=%d past plaintext", start, l, n)
			}
			if !bytes.Equal(buf[:n], pt[start:end]) {
				t.Fatalf("ReadAt(%d,%d) returned corrupted plaintext", start, l)
			}
		}
	}
	return failures
}

func TestReaderAtModifiedCiphertext(t *testing.T) {
	const plaintextSize = 1024
	for _, mc := range newReaderAtModifyCiphers(t) {
		t.Run(mc.name, func(t *testing.T) {
			pt, ct, err := encryptReaderAt(mc.cipher, plaintextSize)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			headerLen := mc.cipher.HeaderLength()

			t.Run("truncate", func(t *testing.T) {
				// Unlike the sequential Reader, a ReaderAt over a prefix of the
				// ciphertext may legitimately return correct plaintext for
				// segments that lie entirely within the prefix; the assertion
				// here is solely that no read returns corrupted bytes.
				for i := 0; i < len(ct); i += 8 {
					checkReaderAtDetectsTampering(t, mc.cipher, pt, ct[:i])
				}
			})
			t.Run("append", func(t *testing.T) {
				for _, size := range []int{1, mc.segmentSize - len(ct)%mc.segmentSize, mc.segmentSize} {
					ct2 := make([]byte, len(ct)+size)
					copy(ct2, ct)
					if checkReaderAtDetectsTampering(t, mc.cipher, pt, ct2) == 0 {
						t.Errorf("append %d bytes: no read failed", size)
					}
				}
			})
			t.Run("flip bits", func(t *testing.T) {
				for i := range ct {
					ct2 := make([]byte, len(ct))
					copy(ct2, ct)
					ct2[i] ^= 1
					if checkReaderAtDetectsTampering(t, mc.cipher, pt, ct2) == 0 {
						t.Errorf("flip byte %d: no read failed", i)
					}
				}
			})
			t.Run("delete segments", func(t *testing.T) {
				for i := 0; i < len(ct)/mc.segmentSize+1; i++ {
					start, end := segmentPos(mc.segmentSize, mc.firstSegmentOffset, headerLen, i)
					if start > len(ct) {
						break
					}
					if end > len(ct) {
						end = len(ct)
					}
					ct2 := make([]byte, 0, len(ct))
					ct2 = append(ct2, ct[:start]...)
					ct2 = append(ct2, ct[end:]...)
					if checkReaderAtDetectsTampering(t, mc.cipher, pt, ct2) == 0 {
						t.Errorf("delete segment %d: no read failed", i)
					}
				}
			})
			t.Run("duplicate segments", func(t *testing.T) {
				for i := 0; i < len(ct)/mc.segmentSize+1; i++ {
					start, end := segmentPos(mc.segmentSize, mc.firstSegmentOffset, headerLen, i)
					if start > len(ct) {
						break
					}
					if end > len(ct) {
						end = len(ct)
					}
					ct2 := make([]byte, 0, len(ct)+end-start)
					ct2 = append(ct2, ct[:end]...)
					ct2 = append(ct2, ct[start:]...)
					if checkReaderAtDetectsTampering(t, mc.cipher, pt, ct2) == 0 {
						t.Errorf("duplicate segment %d: no read failed", i)
					}
				}
			})
			t.Run("modify aad", func(t *testing.T) {
				for i := range aad {
					aad2 := make([]byte, len(aad))
					copy(aad2, aad)
					aad2[i] ^= 1
					r, err := mc.cipher.NewDecryptingReaderAt(bytes.NewReader(ct), int64(len(ct)), aad2)
					if err != nil {
						continue
					}
					buf := make([]byte, 16)
					if _, err := r.ReadAt(buf, 0); err == nil {
						t.Errorf("modified aad byte %d: ReadAt succeeded, want error", i)
					}
				}
			})
		})
	}
}

func encryptReaderAt(cipher readerAtCipher, ptSize int) ([]byte, []byte, error) {
	pt := make([]byte, ptSize)
	for i := range pt {
		pt[i] = byte(i % 251)
	}
	var buf bytes.Buffer
	w, err := cipher.NewEncryptingWriter(&buf, aad)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(pt); err != nil {
		return nil, nil, err
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	return pt, buf.Bytes(), nil
}
