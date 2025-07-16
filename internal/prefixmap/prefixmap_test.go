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

package prefixmap_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/internal/prefixmap"
)

func TestInsert_FailsWithInvalidPrefix(t *testing.T) {
	pm := prefixmap.New[int]()
	if err := pm.Insert("ab", 1); err == nil {
		t.Errorf("pm.Insert(\"ab\", 1) err = nil, want error")
	}
	if err := pm.Insert("ababab", 1); err == nil {
		t.Errorf("pm.Insert(\"ababab\", 1) err = nil, want error")
	}
}

func TestPrimitivesMatchingPrefix_Empty(t *testing.T) {
	t.Run("nil prefix", func(t *testing.T) {
		var got []int
		for e := range prefixmap.New[int]().PrimitivesMatchingPrefix(nil) {
			got = append(got, e)
		}
		if len(got) != 0 {
			t.Errorf("pm.PrimitivesMatchingPrefix(%q) = %v, want empty", "", got)
		}
	})
	t.Run("empty prefix", func(t *testing.T) {
		var got []int
		for e := range prefixmap.New[int]().PrimitivesMatchingPrefix([]byte("")) {
			got = append(got, e)
		}
		if len(got) != 0 {
			t.Errorf("pm.PrimitivesMatchingPrefix(%q) = %v, want empty", "", got)
		}
	})
	t.Run("non-empty prefix", func(t *testing.T) {
		var got []int
		for e := range prefixmap.New[int]().PrimitivesMatchingPrefix([]byte("abcde")) {
			got = append(got, e)
		}
		if len(got) != 0 {
			t.Errorf("pm.PrimitivesMatchingPrefix(%q) = %v, want empty", "", got)
		}
	})
}

func TestPrimitivesMatchingPrefix(t *testing.T) {
	pm := prefixmap.New[int]()
	if err := pm.Insert("abcde", 1); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", "abcde", err)
	}
	if err := pm.Insert("abcde", 2); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", "abcde", err)
	}
	if err := pm.Insert("abcde", 3); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", "abcde", err)
	}
	if err := pm.Insert("fghil", 4); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", "fghil", err)
	}
	if err := pm.Insert("fghil", 5); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", "fghil", err)
	}
	if err := pm.Insert(prefixmap.EmptyPrefix, 6); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", prefixmap.EmptyPrefix, err)
	}
	if err := pm.Insert(prefixmap.EmptyPrefix, 7); err != nil {
		t.Errorf("m.Insert(%v) err = %v, want nil", prefixmap.EmptyPrefix, err)
	}
	for _, tc := range []struct {
		name   string
		prefix []byte
		want   []int
	}{
		{
			name:   "existing prefix",
			prefix: []byte("abcde"),
			want:   []int{1, 2, 3, 6, 7},
		},
		{
			name:   "larger prefix with existing prefix",
			prefix: []byte("abcdefghil"),
			want:   []int{1, 2, 3, 6, 7},
		},
		{
			name:   "non-existing prefix",
			prefix: []byte("ddddd"),
			want:   []int{6, 7},
		},
		{
			name:   "empty prefix",
			prefix: []byte(prefixmap.EmptyPrefix),
			want:   []int{6, 7},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []int
			for e := range pm.PrimitivesMatchingPrefix(tc.prefix) {
				got = append(got, e)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("pm.PrimitivesMatchingPrefix(%q) diff (-want +got):\n%s", tc.prefix, diff)
			}
		})
	}
}
