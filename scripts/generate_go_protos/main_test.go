// Copyright 2026 Google LLC
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

package main

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"testing"
)

func TestVerifyChecksum(t *testing.T) {
	// SHA256 of "abc", from FIPS 180-2.
	const abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	for _, tc := range []struct {
		name   string
		data   string
		wantOK bool
	}{
		{name: "match", data: "abc", wantOK: true},
		{name: "mismatch", data: "abd", wantOK: false},
		{name: "empty", data: "", wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyChecksum([]byte(tc.data), abcSHA256); (err == nil) != tc.wantOK {
				t.Errorf("verifyChecksum(%q, SHA256 of \"abc\") = %v, want success: %t", tc.data, err, tc.wantOK)
			}
		})
	}
}

// newZip returns a zip archive with the given files, mapping names to contents.
func newZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip.Writer.Create(%q) failed: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("writing zip entry %q failed: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip.Writer.Close() failed: %v", err)
	}
	return buf.Bytes()
}

func TestExtractProtoc(t *testing.T) {
	archive := newZip(t, map[string]string{"readme.txt": "readme", "bin/protoc": "the binary", "include/a.proto": "a"})
	got, err := extractProtoc(archive)
	if err != nil {
		t.Fatalf("extractProtoc() failed: %v", err)
	}
	if want := "the binary"; string(got) != want {
		t.Errorf("extractProtoc() = %q, want %q", got, want)
	}
}

func TestExtractProtocErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		archive []byte
	}{
		{name: "no_bin_protoc", archive: newZip(t, map[string]string{"readme.txt": "readme", "protoc": "wrong place"})},
		{name: "not_a_zip_archive", archive: []byte("not a zip archive")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := extractProtoc(tc.archive); err == nil {
				t.Errorf("extractProtoc() = %q, want error", got)
			}
		})
	}
}

func TestParseToolchain(t *testing.T) {
	for _, tc := range []struct {
		name  string
		goMod string
		want  string // Empty if parseToolchain is expected to fail.
	}{
		{name: "tink_go", goMod: "module m\n\ngo 1.26.0\n\ntoolchain go1.26.10\n\nrequire x v1.0.0\n", want: "go1.26.10"},
		{name: "odd_spacing", goMod: "module m\r\n\t toolchain \t go1.27rc1  \r\n", want: "go1.27rc1"},
		{name: "trailing_comment", goMod: "toolchain go1.27.3 // pinned\n", want: "go1.27.3"},
		{name: "missing", goMod: "module m\n\ngo 1.26.0\n"},
		{name: "commented_out", goMod: "module m\n// toolchain go1.26.10\n"},
		{name: "no_argument", goMod: "module m\ntoolchain\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseToolchain([]byte(tc.goMod))
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Errorf("parseToolchain(%q) = %q, %v, want %q", tc.goMod, got, err, tc.want)
			}
		})
	}
}

func TestOutputPath(t *testing.T) {
	for _, tc := range []struct {
		protoFile string
		want      string
	}{
		{protoFile: "tink.proto", want: "tink_go_proto/tink.pb.go"},
		{protoFile: "aes_ctr_hmac_aead.proto", want: "aes_ctr_hmac_aead_go_proto/aes_ctr_hmac_aead.pb.go"},
	} {
		if got := outputPath(tc.protoFile); got != filepath.FromSlash(tc.want) {
			t.Errorf("outputPath(%q) = %q, want %q", tc.protoFile, got, tc.want)
		}
	}
}
