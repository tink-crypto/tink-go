// Copyright 2019 Google LLC
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

package primitiveset_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/aead/aesgcm"
	"github.com/tink-crypto/tink-go/v2/aead/chacha20poly1305"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/secretdata"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestPrimitvesetNew(t *testing.T) {
	ps := primitiveset.New[any]()
	if ps.Primary != nil || ps.Entries == nil || ps.EntriesInKeysetOrder == nil {
		t.Errorf("expect primary to be nil and primitives is initialized")
	}
}

type testKey struct {
	keyID     uint32
	key       key.Key
	primitive tink.AEAD
	isFull    bool
}

var (
	keyBytes = []byte("01234567890123456789012345678901")
)

func mustCreateAESGCMKey(t *testing.T, variant aesgcm.Variant, keyID uint32) *aesgcm.Key {
	params, err := aesgcm.NewParameters(aesgcm.ParametersOpts{
		Variant:        variant,
		KeySizeInBytes: 32,
		IVSizeInBytes:  12,
		TagSizeInBytes: 16,
	})
	if err != nil {
		t.Fatalf("aesgcm.NewParameters() err = %v, want nil", err)
	}
	sd := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
	key, err := aesgcm.NewKey(sd, keyID, params)
	if err != nil {
		t.Fatalf("aesgcm.NewKey() err = %v, want nil", err)
	}
	return key
}

func mustCreateChaCha20Poly1305Key(t *testing.T, variant chacha20poly1305.Variant, keyID uint32) *chacha20poly1305.Key {
	params, err := chacha20poly1305.NewParameters(variant)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewParameters() err = %v, want nil", err)
	}
	sd := secretdata.NewBytesFromData(keyBytes, insecuresecretdataaccess.Token{})
	key, err := chacha20poly1305.NewKey(sd, keyID, params)
	if err != nil {
		t.Fatalf("chacha20poly1305.NewKey() err = %v, want nil", err)
	}
	return key
}

func TestPrimitivesetAddAndEntriesInKeysetOrder(t *testing.T) {
	keys := []testKey{
		testKey{
			keyID:     0x1234543,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantTink, 0x1234543),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1234543)},
		},
		testKey{
			keyID:     0x7213743,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 0x7213743),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x7213743)},
		},
		testKey{
			keyID:     0,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1111111)},
		},
		testKey{
			keyID:     0x9876543,
			key:       mustCreateChaCha20Poly1305Key(t, chacha20poly1305.VariantTink, 0x9876543),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x9876543)},
			isFull:    true,
		},
	}
	ps := primitiveset.New[tink.AEAD]()
	var got []*primitiveset.Entry[tink.AEAD]
	for _, k := range keys {
		e := &primitiveset.Entry[tink.AEAD]{
			KeyID: k.keyID,
			Key:   k.key,
		}
		if k.isFull {
			e.FullPrimitive = k.primitive
		} else {
			e.Primitive = k.primitive
		}
		got = append(got, e)
		if err := ps.Add(e); err != nil {
			t.Fatalf("ps.Add() err = %v, want nil", err)
		}
	}
	want := []*primitiveset.Entry[tink.AEAD]{
		{
			KeyID:     0x1234543,
			Primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1234543)},
			Key:       keys[0].key,
		},
		{
			KeyID:     0x7213743,
			Primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x7213743)},
			Key:       keys[1].key,
		},
		{
			KeyID:     0,
			Primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1111111)},
			Key:       keys[2].key,
		},
		{
			KeyID:         0x9876543,
			FullPrimitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x9876543)},
			Key:           keys[3].key,
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("got diff (-want +got):\n%s", diff)
	}
	if !cmp.Equal(ps.EntriesInKeysetOrder, want) {
		t.Errorf("EntriesInKeysetOrder = %v, want = %v", ps.EntriesInKeysetOrder, want)
	}
}

func TestPrimitivesetRawEntries(t *testing.T) {
	keys := []testKey{
		testKey{
			keyID:     0x1234543,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantTink, 0x1234543),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1234543)},
		},
		testKey{
			keyID:     0x7213743,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 0x7213743),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x7213743)},
		},
		testKey{
			keyID:     0,
			key:       mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1111111)},
		},
		testKey{
			keyID:     0x9876543,
			key:       mustCreateChaCha20Poly1305Key(t, chacha20poly1305.VariantNoPrefix, 0),
			primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x9876543)},
			isFull:    true,
		},
	}
	ps := primitiveset.New[tink.AEAD]()
	for _, k := range keys {
		e := &primitiveset.Entry[tink.AEAD]{
			KeyID: k.keyID,
			Key:   k.key,
		}
		if k.isFull {
			e.FullPrimitive = k.primitive
		} else {
			e.Primitive = k.primitive
		}
		if err := ps.Add(e); err != nil {
			t.Fatalf("ps.Add() err = %v, want nil", err)
		}
	}
	got, err := ps.RawEntries()
	if err != nil {
		t.Errorf("RawEntries() err = %v, want nil", err)
	}
	want := []*primitiveset.Entry[tink.AEAD]{
		{
			KeyID:     0,
			Primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1111111)},
			Key:       keys[2].key,
		},
		{
			KeyID:         0x9876543,
			FullPrimitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x9876543)},
			Key:           keys[3].key,
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("ps.RawEntries() diff (-want +got):\n%s", diff)
	}
}

type primitive struct {
	primitive tink.AEAD
	isFull    bool
}

func TestPrimitivesetPrefixedEntries(t *testing.T) {
	type testCase struct {
		tag           string
		prefix        string
		entries       []*primitiveset.Entry[tink.AEAD]
		wantForPrefix []*primitiveset.Entry[tink.AEAD]
	}
	for _, tc := range []testCase{
		{
			tag:    "legacy Prefix",
			prefix: string([]byte{0, 0, 18, 214, 111}), // LEGACY_PREFIX + 1234543,
			entries: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 1234543),
				},
				{
					KeyID:         7213743,
					FullPrimitive: &testutil.DummyAEAD{Name: "2"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 7213743),
				},
			},
			wantForPrefix: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 1234543),
				},
			},
		},
		{
			tag:    "raw prefix",
			prefix: "",
			entries: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
				},
				{
					KeyID:         7213743,
					FullPrimitive: &testutil.DummyAEAD{Name: "2"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantCrunchy, 7213743),
				},
				{
					KeyID:         9876543,
					FullPrimitive: &testutil.DummyAEAD{Name: "3"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
				},
			},
			wantForPrefix: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
				},
				{
					KeyID:         9876543,
					FullPrimitive: &testutil.DummyAEAD{Name: "3"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
				},
			},
		},
		{
			tag:    "tink prefix multiple entries",
			prefix: string([]byte{1, 0, 18, 214, 111}), // TINK_PREFIX + 1234543
			entries: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantTink, 1234543),
				},
				{
					KeyID:         1234543,
					FullPrimitive: &testutil.DummyAEAD{Name: "2"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantTink, 1234543),
				},
				{
					KeyID:         9876543,
					FullPrimitive: &testutil.DummyAEAD{Name: "3"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantNoPrefix, 0),
				},
				{
					KeyID:     7213743,
					Primitive: &testutil.DummyAEAD{Name: "2"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantTink, 7213743),
				},
			},
			wantForPrefix: []*primitiveset.Entry[tink.AEAD]{
				{
					KeyID:     1234543,
					Primitive: &testutil.DummyAEAD{Name: "1"},
					Key:       mustCreateAESGCMKey(t, aesgcm.VariantTink, 1234543),
				},
				{
					KeyID:         1234543,
					FullPrimitive: &testutil.DummyAEAD{Name: "2"},
					Key:           mustCreateAESGCMKey(t, aesgcm.VariantTink, 1234543),
				},
			},
		},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			ps := primitiveset.New[tink.AEAD]()
			for i := 0; i < len(tc.entries); i++ {
				err := ps.Add(tc.entries[i])
				if err != nil {
					t.Fatalf("ps.Add() err = %v, want nil", err)
				}
			}
			got, err := ps.EntriesForPrefix(tc.prefix)
			if err != nil {
				t.Errorf("EntriesForPrefix() err =  %v, want nil", err)
			}
			if diff := cmp.Diff(got, tc.wantForPrefix); diff != "" {
				t.Errorf("EntriesForPrefix() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAddWithInvalidInput(t *testing.T) {
	ps := primitiveset.New[tink.AEAD]()
	type testCase struct {
		name  string
		entry *primitiveset.Entry[tink.AEAD]
	}
	for _, tc := range []testCase{
		{
			name: "nil key",
			entry: &primitiveset.Entry[tink.AEAD]{
				KeyID:     0,
				Primitive: &testutil.DummyAEAD{Name: fmt.Sprintf("AESGCM_%d", 0x1111111)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ps.Add(tc.entry); err == nil {
				t.Errorf("ps.Add() err = nil, want non-nil")
			}
		})
	}
}
