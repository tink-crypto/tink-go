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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// mustListPbGoFiles returns the files dir/*/*.pb.go as sorted paths relative to
// dir.
func mustListPbGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*.pb.go")) // Sorted.
	if err != nil {
		t.Fatalf("filepath.Glob() failed: %v", err)
	}
	for i, path := range paths {
		paths[i] = path[len(dir)+1:]
	}
	return paths
}

// TestGeneratedProtosAreUpToDate regenerates the Go protocol buffer files into
// a temporary directory and compares them with the files in proto/. It is also
// the end-to-end test of this tool.
//
// It downloads protoc and runs the go command in the tink-go module, so it
// only runs if TINK_GO_CHECK_GENERATED_PROTOS is set, as
// kokoro/gcp_ubuntu/gomod/run_tests.sh does.
func TestGeneratedProtosAreUpToDate(t *testing.T) {
	if os.Getenv("TINK_GO_CHECK_GENERATED_PROTOS") == "" {
		t.Skip("skipping: needs network access and the tink-go module; set TINK_GO_CHECK_GENERATED_PROTOS=1 to run")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("skipping: the generator only runs on linux/amd64, this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	t.Chdir(filepath.Join("..", "..")) // The root of the tink-go module.
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("os.ReadFile(go.mod) failed: %v", err)
	}
	toolchain, err := parseToolchain(goMod)
	if err != nil {
		t.Fatalf("parseToolchain() failed: %v", err)
	}
	outDir := t.TempDir()
	if err := generate(t.Context(), t.TempDir(), toolchain, outDir); err != nil {
		t.Fatalf("generate() failed: %v", err)
	}

	checkedIn, generated := mustListPbGoFiles(t, "proto"), mustListPbGoFiles(t, outDir)
	if diff := cmp.Diff(checkedIn, generated); diff != "" {
		t.Errorf("the set of *.pb.go files in proto/ is not up to date; \"-\" files have no .proto file, "+
			"\"+\" files are missing (-checked in +generated):\n%s", diff)
	}
	for _, name := range generated {
		got, err := os.ReadFile(filepath.Join("proto", name))
		if errors.Is(err, fs.ErrNotExist) {
			continue // Reported above as missing.
		}
		if err != nil {
			t.Fatalf("reading the checked-in file failed: %v", err)
		}
		want, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("reading the generated file failed: %v", err)
		}
		if diff := cmp.Diff(strings.Split(string(want), "\n"), strings.Split(string(got), "\n")); diff != "" {
			t.Errorf("proto/%s is not up to date (lines, -want +got):\n%s", name, diff)
		}
	}
	if t.Failed() {
		t.Log("To update the generated files, run \"go run ./scripts/generate_go_protos\" from the root of the repository " +
			"and remove the generated files that have no .proto file. Googlers: use third_party/tink/tools/gen_go_pb.sh instead.")
	}
}

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
