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

package streamingaead_test

import (
	"bytes"
	"io"
	"math/rand"
	"sync"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
)

func encryptForReaderAt(t *testing.T, handle *keyset.Handle, ptSize int) ([]byte, []byte, []byte) {
	t.Helper()
	pt := random.GetRandomBytes(uint32(ptSize))
	aad := random.GetRandomBytes(32)
	a, err := streamingaead.New(handle)
	if err != nil {
		t.Fatalf("streamingaead.New: %v", err)
	}
	var buf bytes.Buffer
	w, err := a.NewEncryptingWriter(&buf, aad)
	if err != nil {
		t.Fatalf("NewEncryptingWriter: %v", err)
	}
	if _, err := w.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return pt, buf.Bytes(), aad
}

func TestNewDecryptingReaderAtSingleKey(t *testing.T) {
	templates := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"AES128GCMHKDF4KB", streamingaead.AES128GCMHKDF4KBKeyTemplate()},
		{"AES256GCMHKDF1MB", streamingaead.AES256GCMHKDF1MBKeyTemplate()},
		{"AES128CTRHMACSHA256Segment4KB", streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate()},
	}
	for _, tmpl := range templates {
		t.Run(tmpl.name, func(t *testing.T) {
			handle, err := keyset.NewHandle(tmpl.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle: %v", err)
			}
			for _, ptSize := range []int{0, 100, 4095, 4096, 4097, 20000} {
				pt, ct, aad := encryptForReaderAt(t, handle, ptSize)
				r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
				if err != nil {
					t.Fatalf("NewDecryptingReaderAt(%d): %v", ptSize, err)
				}
				if got := r.Size(); got != int64(ptSize) {
					t.Errorf("Size() = %d, want %d", got, ptSize)
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

func TestDecryptingReaderAtConcurrent(t *testing.T) {
	templates := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{"AES128GCMHKDF4KB", streamingaead.AES128GCMHKDF4KBKeyTemplate()},
		{"AES128CTRHMACSHA256Segment4KB", streamingaead.AES128CTRHMACSHA256Segment4KBKeyTemplate()},
	}
	for _, tmpl := range templates {
		t.Run(tmpl.name, func(t *testing.T) {
			handle, err := keyset.NewHandle(tmpl.template)
			if err != nil {
				t.Fatalf("keyset.NewHandle: %v", err)
			}
			pt, ct, aad := encryptForReaderAt(t, handle, 32*1024)
			r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
			if err != nil {
				t.Fatalf("NewDecryptingReaderAt: %v", err)
			}
			var wg sync.WaitGroup
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(seed int64) {
					defer wg.Done()
					rng := rand.New(rand.NewSource(seed))
					for i := 0; i < 50; i++ {
						off := rng.Int63n(int64(len(pt)))
						l := rng.Intn(256) + 1
						buf := make([]byte, l)
						n, err := r.ReadAt(buf, off)
						end := int(off) + l
						if end > len(pt) {
							end = len(pt)
						}
						if n != end-int(off) || !bytes.Equal(buf[:n], pt[off:end]) {
							t.Errorf("mismatch at off=%d (err=%v)", off, err)
							return
						}
					}
				}(int64(g))
			}
			wg.Wait()
		})
	}
}

func TestNewDecryptingReaderAtMultipleKeys(t *testing.T) {
	ks := testutil.NewTestAESGCMHKDFKeyset()
	handle, err := testkeyset.NewHandle(ks)
	if err != nil {
		t.Fatalf("testkeyset.NewHandle: %v", err)
	}

	t.Run("encryptWithPrimary", func(t *testing.T) {
		pt, ct, aad := encryptForReaderAt(t, handle, 5000)
		r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
		if err != nil {
			t.Fatalf("NewDecryptingReaderAt: %v", err)
		}
		got := make([]byte, len(pt))
		if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
			t.Fatalf("ReadAt: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Error("plaintext mismatch")
		}
	})

	t.Run("encryptWithNonPrimary", func(t *testing.T) {
		rawKey := ks.Key[1]
		ks2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
		handle2, err := testkeyset.NewHandle(ks2)
		if err != nil {
			t.Fatalf("testkeyset.NewHandle: %v", err)
		}
		pt, ct, aad := encryptForReaderAt(t, handle2, 5000)
		// Decrypt with the full keyset; should find the right key.
		r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
		if err != nil {
			t.Fatalf("NewDecryptingReaderAt: %v", err)
		}
		got := make([]byte, len(pt))
		if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
			t.Fatalf("ReadAt: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Error("plaintext mismatch")
		}
		// Subsequent reads use the matched key.
		buf := make([]byte, 100)
		if _, err := r.ReadAt(buf, 1000); err != nil {
			t.Errorf("second ReadAt: %v", err)
		}
		if !bytes.Equal(buf, pt[1000:1100]) {
			t.Error("second read mismatch")
		}
	})

	t.Run("noMatchingKey", func(t *testing.T) {
		other := testutil.NewTestAESGCMHKDFKeyset()
		otherHandle, err := testkeyset.NewHandle(other)
		if err != nil {
			t.Fatalf("testkeyset.NewHandle: %v", err)
		}
		_, ct, aad := encryptForReaderAt(t, otherHandle, 1000)
		r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
		if err != nil {
			t.Fatalf("NewDecryptingReaderAt: %v", err)
		}
		buf := make([]byte, 10)
		if _, err := r.ReadAt(buf, 0); err == nil {
			t.Error("ReadAt with wrong keyset succeeded, want error")
		}
	})
}

func TestDecryptingReaderAtCiphertextRange(t *testing.T) {
	handle, err := keyset.NewHandle(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle: %v", err)
	}
	pt, ct, aad := encryptForReaderAt(t, handle, 20000)
	r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), aad)
	if err != nil {
		t.Fatalf("NewDecryptingReaderAt: %v", err)
	}

	// CiphertextRange must cover bytes sufficient to satisfy the read; verify by
	// decrypting using only that range.
	off, n := r.CiphertextRange(5000, 1000)
	if off <= 0 || n <= 0 || off+n > int64(len(ct)) {
		t.Fatalf("CiphertextRange = [%d,%d), out of bounds [0,%d)", off, off+n, len(ct))
	}
	partial := make([]byte, len(ct))
	copy(partial[off:off+n], ct[off:off+n])
	// The header is read at construction time, so include it in the partial copy.
	copy(partial[:off], ct[:off])
	for i := off + n; i < int64(len(ct)); i++ {
		partial[i] = 0
	}
	r2, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(partial), aad)
	if err != nil {
		t.Fatalf("NewDecryptingReaderAt(partial): %v", err)
	}
	buf := make([]byte, 1000)
	if _, err := r2.ReadAt(buf, 5000); err != nil {
		t.Fatalf("ReadAt(partial): %v", err)
	}
	if !bytes.Equal(buf, pt[5000:6000]) {
		t.Error("partial-range read mismatch")
	}
}

func TestDecryptingReaderAtWithSectionReader(t *testing.T) {
	handle, err := keyset.NewHandle(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle: %v", err)
	}
	pt, ct, aad := encryptForReaderAt(t, handle, 1000)
	sr := io.NewSectionReader(bytes.NewReader(ct), 0, int64(len(ct)))
	r, err := streamingaead.NewDecryptingReaderAt(handle, sr, aad)
	if err != nil {
		t.Fatalf("NewDecryptingReaderAt: %v", err)
	}
	got := make([]byte, len(pt))
	if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Error("plaintext mismatch")
	}
}

// wrongSizeReaderAt reports a deliberately incorrect Size while delegating
// ReadAt to the underlying reader.
type wrongSizeReaderAt struct {
	io.ReaderAt
	size int64
}

func (w wrongSizeReaderAt) Size() int64 { return w.size }

func TestDecryptingReaderAtWrongSize(t *testing.T) {
	handle, err := keyset.NewHandle(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle: %v", err)
	}
	pt, ct, aad := encryptForReaderAt(t, handle, 10000)
	for _, tc := range []struct {
		name  string
		delta int64
	}{
		{"minus1", -1},
		{"minusSegment", -4096},
		{"plus1", 1},
		{"plusSegment", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := wrongSizeReaderAt{ReaderAt: bytes.NewReader(ct), size: int64(len(ct)) + tc.delta}
			r, err := streamingaead.NewDecryptingReaderAt(handle, src, aad)
			if err != nil {
				// Construction may legitimately reject some sizes.
				return
			}
			// A read in the first segment must either fail or return correct
			// bytes; an incorrect size must not cause silent corruption.
			buf := make([]byte, 16)
			if n, err := r.ReadAt(buf, 0); err == nil {
				if !bytes.Equal(buf[:n], pt[:n]) {
					t.Fatalf("ReadAt(0) returned corrupted plaintext")
				}
			}
			// A read covering the final segment must fail: the wrong size
			// changes either the last-segment nonce flag or the segment
			// boundaries, so authentication of the affected segment must fail.
			if _, err := r.ReadAt(buf, int64(len(pt))-16); err == nil {
				t.Errorf("ReadAt near end with wrong size %+d succeeded, want error", tc.delta)
			}
		})
	}
}

func TestDecryptingReaderAtBadAAD(t *testing.T) {
	handle, err := keyset.NewHandle(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle: %v", err)
	}
	_, ct, _ := encryptForReaderAt(t, handle, 1000)
	r, err := streamingaead.NewDecryptingReaderAt(handle, bytes.NewReader(ct), []byte("wrong"))
	if err != nil {
		t.Fatalf("NewDecryptingReaderAt: %v", err)
	}
	buf := make([]byte, 10)
	if _, err := r.ReadAt(buf, 0); err == nil {
		t.Error("ReadAt with wrong AAD succeeded, want error")
	}
}
