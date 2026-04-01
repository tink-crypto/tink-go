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

package noncebased_test

import (
	"bytes"
	"io"
	"math"
	"math/rand"
	"sync"
	"testing"

	"github.com/tink-crypto/tink-go/v2/streamingaead/subtle/noncebased"
)

// readerAtTestParams describes a (plaintext size, segment geometry) combination
// used by the ReaderAt tests.
type readerAtTestParams struct {
	name                         string
	plaintextSize                int
	nonceSize                    int
	noncePrefixSize              int
	plaintextSegmentSize         int
	firstCiphertextSegmentOffset int
}

func readerAtTestCases() []readerAtTestParams {
	return []readerAtTestParams{
		{"aligned", 100, 10, 5, 20, 10},
		{"unaligned", 110, 10, 5, 20, 10},
		{"twoSegments", 25, 10, 5, 20, 10},
		{"shortPlaintext", 1, 10, 5, 100, 10},
		{"empty", 0, 10, 5, 100, 10},
		{"manySegments", 1000, 10, 5, 17, 10},
		{"exactlyFirstSegment", 10, 10, 5, 20, 10},
	}
}

// newReaderAtFixture encrypts a deterministic plaintext via the noncebased
// Writer and returns the plaintext, the full ciphertext (with a synthetic
// header of firstCiphertextSegmentOffset bytes), and a constructed ReaderAt.
func newReaderAtFixture(t testing.TB, tc readerAtTestParams) ([]byte, []byte, *noncebased.ReaderAt) {
	t.Helper()
	pt, segments, noncePrefix, err := testEncrypt(tc.plaintextSize, tc.noncePrefixSize, noncebased.WriterParams{
		NonceSize:                    tc.nonceSize,
		PlaintextSegmentSize:         tc.plaintextSegmentSize,
		FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("testEncrypt: %v", err)
	}
	r, err := noncebased.NewReaderAt(noncebased.ReaderAtParams{
		R:                            bytes.NewReader(segments),
		CiphertextSize:               int64(len(segments)),
		SegmentDecrypter:             testDecrypterWithDst{},
		NonceSize:                    tc.nonceSize,
		NoncePrefix:                  noncePrefix,
		CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
		PlaintextSegmentSize:         tc.plaintextSegmentSize,
		FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("NewReaderAt: %v", err)
	}
	return pt, segments, r
}

func TestReaderAtSize(t *testing.T) {
	for _, tc := range readerAtTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			pt, _, r := newReaderAtFixture(t, tc)
			if got, want := r.Size(), int64(len(pt)); got != want {
				t.Errorf("Size() = %d, want %d", got, want)
			}
		})
	}
}

func TestReaderAtFullRead(t *testing.T) {
	for _, tc := range readerAtTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			pt, _, r := newReaderAtFixture(t, tc)
			got := make([]byte, len(pt))
			n, err := r.ReadAt(got, 0)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt(0) err = %v", err)
			}
			if n != len(pt) {
				t.Fatalf("ReadAt(0) n = %d, want %d", n, len(pt))
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("plaintext mismatch")
			}
		})
	}
}

func TestReaderAtPastEnd(t *testing.T) {
	for _, tc := range readerAtTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			pt, _, r := newReaderAtFixture(t, tc)
			buf := make([]byte, 4)
			n, err := r.ReadAt(buf, int64(len(pt)))
			if n != 0 || err != io.EOF {
				t.Errorf("ReadAt(len(pt)) = (%d, %v), want (0, io.EOF)", n, err)
			}
		})
	}
}

func BenchmarkReaderAtParallel(b *testing.B) {
	tc := readerAtTestParams{"bench", 64 * 1024, 12, 7, 4096, 12}
	pt, _, r := newReaderAtFixture(b, tc)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rng := rand.New(rand.NewSource(rand.Int63()))
		buf := make([]byte, 256)
		for pb.Next() {
			off := rng.Int63n(int64(len(pt) - len(buf)))
			if _, err := r.ReadAt(buf, off); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestReaderAtOffsets(t *testing.T) {
	for _, tc := range readerAtTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			pt, _, r := newReaderAtFixture(t, tc)
			seg0Pt := tc.plaintextSegmentSize - tc.firstCiphertextSegmentOffset
			reads := []struct {
				name string
				off  int64
				len  int
			}{
				{"start", 0, 5},
				{"midSegment", 3, 4},
				{"segmentBoundary", int64(seg0Pt), 5},
				{"acrossTwoSegments", int64(seg0Pt) - 2, 6},
				{"acrossManySegments", 0, 3*tc.plaintextSegmentSize + 1},
				{"tail", int64(len(pt)) - 3, 3},
				{"atEOF", int64(len(pt)), 1},
				{"pastEOF", int64(len(pt)) + 5, 1},
			}
			for _, rd := range reads {
				t.Run(rd.name, func(t *testing.T) {
					if rd.off < 0 {
						return
					}
					buf := make([]byte, rd.len)
					n, err := r.ReadAt(buf, rd.off)
					var want []byte
					if rd.off < int64(len(pt)) {
						end := rd.off + int64(rd.len)
						if end > int64(len(pt)) {
							end = int64(len(pt))
						}
						want = pt[rd.off:end]
					}
					if n != len(want) {
						t.Fatalf("n = %d, want %d (err = %v)", n, len(want), err)
					}
					if !bytes.Equal(buf[:n], want) {
						t.Errorf("data mismatch at off=%d", rd.off)
					}
					if n < rd.len && err != io.EOF {
						t.Errorf("short read at off=%d returned err = %v, want io.EOF", rd.off, err)
					}
				})
			}
		})
	}
}

func TestReaderAtRandomAccess(t *testing.T) {
	tc := readerAtTestParams{"random", 5000, 10, 5, 23, 10}
	pt, _, r := newReaderAtFixture(t, tc)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		off := rng.Int63n(int64(len(pt)))
		l := rng.Intn(100) + 1
		buf := make([]byte, l)
		n, err := r.ReadAt(buf, off)
		end := int(off) + l
		if end > len(pt) {
			end = len(pt)
		}
		want := pt[off:end]
		if n != len(want) {
			t.Fatalf("iter %d: n = %d, want %d (err = %v)", i, n, len(want), err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("iter %d: mismatch at off=%d", i, off)
		}
		if n < l && err != io.EOF {
			t.Fatalf("iter %d: short read err = %v, want io.EOF", i, err)
		}
	}
}

func TestReaderAtConcurrent(t *testing.T) {
	tc := readerAtTestParams{"concurrent", 4000, 10, 5, 31, 10}
	pt, _, r := newReaderAtFixture(t, tc)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 50; i++ {
				off := rng.Int63n(int64(len(pt)))
				l := rng.Intn(64) + 1
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
}

func TestReaderAtCiphertextRange(t *testing.T) {
	tc := readerAtTestParams{"range", 200, 10, 5, 20, 10}
	_, ct, r := newReaderAtFixture(t, tc)
	ctSegSize := int64(tc.plaintextSegmentSize + tc.nonceSize)
	seg0Ct := ctSegSize - int64(tc.firstCiphertextSegmentOffset)
	seg0Pt := int64(tc.plaintextSegmentSize - tc.firstCiphertextSegmentOffset)

	cases := []struct {
		name              string
		ptOff, ptLen      int64
		wantOff, wantHigh int64
	}{
		{"firstByte", 0, 1, 0, seg0Ct},
		{"spanTwo", seg0Pt - 1, 2, 0, seg0Ct + ctSegSize},
		{"secondSeg", seg0Pt, 1, seg0Ct, seg0Ct + ctSegSize},
		{"full", 0, r.Size(), 0, int64(len(ct))},
		{"zeroLen", 5, 0, 0, 0},
		{"pastEOF", r.Size() + 1, 5, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotOff, gotN := r.CiphertextRange(c.ptOff, c.ptLen)
			if gotOff != c.wantOff || gotOff+gotN != c.wantHigh {
				t.Errorf("CiphertextRange(%d,%d) = [%d,%d), want [%d,%d)",
					c.ptOff, c.ptLen, gotOff, gotOff+gotN, c.wantOff, c.wantHigh)
			}
		})
	}
}

func TestReaderAtTamperedCiphertext(t *testing.T) {
	tc := readerAtTestParams{"tamper", 100, 10, 5, 20, 10}
	_, ct, _ := newReaderAtFixture(t, tc)
	// Flip a byte inside segment_1.
	seg0Ct := tc.plaintextSegmentSize + tc.nonceSize - tc.firstCiphertextSegmentOffset
	ct[seg0Ct+2] ^= 0x01
	r, err := noncebased.NewReaderAt(noncebased.ReaderAtParams{
		R:                            bytes.NewReader(ct),
		CiphertextSize:               int64(len(ct)),
		SegmentDecrypter:             testDecrypterWithDst{},
		NonceSize:                    tc.nonceSize,
		NoncePrefix:                  make([]byte, tc.noncePrefixSize),
		CiphertextSegmentSize:        tc.plaintextSegmentSize + tc.nonceSize,
		PlaintextSegmentSize:         tc.plaintextSegmentSize,
		FirstCiphertextSegmentOffset: tc.firstCiphertextSegmentOffset,
	})
	if err != nil {
		t.Fatalf("NewReaderAt: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := r.ReadAt(buf, int64(tc.plaintextSegmentSize-tc.firstCiphertextSegmentOffset)); err == nil {
		t.Error("ReadAt of tampered segment succeeded, want error")
	}
}

func TestReaderAtNegativeOffset(t *testing.T) {
	tc := readerAtTestParams{"neg", 100, 10, 5, 20, 10}
	_, _, r := newReaderAtFixture(t, tc)
	if _, err := r.ReadAt(make([]byte, 4), -1); err == nil {
		t.Error("ReadAt(-1) succeeded, want error")
	}
}

func TestNewReaderAtInvalidParams(t *testing.T) {
	base := noncebased.ReaderAtParams{
		R:                            bytes.NewReader(make([]byte, 100)),
		CiphertextSize:               100,
		SegmentDecrypter:             testDecrypterWithDst{},
		NonceSize:                    10,
		NoncePrefix:                  make([]byte, 5),
		CiphertextSegmentSize:        30,
		PlaintextSegmentSize:         20,
		FirstCiphertextSegmentOffset: 10,
	}
	cases := []struct {
		name   string
		mutate func(*noncebased.ReaderAtParams)
	}{
		{"nonceTooShort", func(p *noncebased.ReaderAtParams) { p.NonceSize = 5 }},
		{"segmentSizes", func(p *noncebased.ReaderAtParams) { p.PlaintextSegmentSize = 30 }},
		{"ciphertextTooShort", func(p *noncebased.ReaderAtParams) { p.CiphertextSize = 5 }},
		{"offsetTooLarge", func(p *noncebased.ReaderAtParams) { p.FirstCiphertextSegmentOffset = 25 }},
		{"remainderTooShort", func(p *noncebased.ReaderAtParams) { p.CiphertextSize = 21 }},
		{"sizeOverflow", func(p *noncebased.ReaderAtParams) { p.CiphertextSize = math.MaxInt64 }},
		{"tooManySegments", func(p *noncebased.ReaderAtParams) {
			p.CiphertextSize = int64(p.CiphertextSegmentSize) * (int64(math.MaxUint32) + 2)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base
			c.mutate(&p)
			if _, err := noncebased.NewReaderAt(p); err == nil {
				t.Error("NewReaderAt succeeded, want error")
			}
		})
	}
}
