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

// The generate_go_protos command regenerates the Go protocol buffer files of
// tink-go. Run it from the root of the tink-go module:
//
//	go run ./scripts/generate_go_protos
//
// For each proto/<name>.proto it writes proto/<name>_go_proto/<name>.pb.go.
//
// To make the output reproducible, the tools are pinned: protoc is downloaded
// at a fixed version and its SHA256 checksum is verified, and protoc-gen-go is
// built from the google.golang.org/protobuf version in go.mod with the Go
// toolchain named there. The tools live in a temporary directory that is
// removed on exit; nothing is installed. Only Linux x86_64 is supported.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// The protoc release to use; see
// https://github.com/protocolbuffers/protobuf/releases. Release 21.12 reports
// itself as "libprotoc 3.21.12" ("protoc v3.21.12" in the generated files).
const (
	protocURL    = "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip"
	protocSHA256 = "3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"
)

// protocGenGoPackage is the package of protoc-gen-go. It deliberately has no
// version.
//
// protoc-gen-go is the cmd/protoc-gen-go package of the
// google.golang.org/protobuf module, which tink-go already requires for the
// protobuf runtime. Building the package inside the tink-go module therefore
// uses the version in go.mod, verified with go.sum, and adds no dependency.
// With -mod=readonly the build fails instead of modifying go.mod or go.sum.
// The generator thus always matches the runtime, and upgrading the module in
// go.mod upgrades the generator.
const (
	protocGenGoPackage = "google.golang.org/protobuf/cmd/protoc-gen-go"
	scriptID           = "16cfc9a72a6ec850a176"
)

func printHeader() {
	fmt.Println("================================================================================")
	fmt.Printf("Tink Script ID: %s (to quickly find the script from logs)\n", scriptID)
	fmt.Println("================================================================================")
}

func main() {
	// Stop on these signals, so that the work directory is removed.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	printHeader()
	err := run(ctx)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("only linux/amd64 is supported, this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		return fmt.Errorf("this must run from the root of the tink-go module: %v", err)
	}
	toolchain, err := parseToolchain(goMod)
	if err != nil {
		return err
	}
	workDir, err := os.MkdirTemp("", "tink-go-protos-")
	if err != nil {
		return err
	}
	fmt.Println("Created the work directory", workDir)
	defer func() {
		fmt.Println("Removing the work directory", workDir)
		os.RemoveAll(workDir)
	}()
	return generate(ctx, workDir, toolchain, "proto")
}

// generate installs the tools in workDir and writes
// outDir/<name>_go_proto/<name>.pb.go for each proto/<name>.proto.
func generate(ctx context.Context, workDir, toolchain, outDir string) error {
	tinkGoDir, err := os.Getwd()
	if err != nil {
		return err
	}
	protoFiles, err := filepath.Glob("proto/*.proto") // Sorted.
	if err != nil || len(protoFiles) == 0 {
		return fmt.Errorf("no proto/*.proto files found in %s (error: %v)", tinkGoDir, err)
	}

	fmt.Println("Downloading protoc from", protocURL, "and verifying its checksum")
	protoc := filepath.Join(workDir, "protoc")
	if err := installProtoc(ctx, protoc); err != nil {
		return err
	}

	// The build is pinned to the Go toolchain in go.mod, because protoc-gen-go
	// formats its output with the toolchain it is built with: for example,
	// Go 1.27.3 formats a comment in ecdsa.pb.go differently from Go 1.26.10.
	// The go command downloads that toolchain if it is not the local one.
	// GOOS and GOARCH are set because the plugin runs on this machine, even if
	// the caller cross-compiles tink-go.
	fmt.Println("Building protoc-gen-go from", protocGenGoPackage, "with", toolchain)
	plugin := filepath.Join(workDir, "protoc-gen-go")
	env := []string{"GOTOOLCHAIN=" + toolchain, "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}
	if err := runCommand(ctx, "", env, "go", "build", "-mod=readonly", "-o", plugin, protocGenGoPackage); err != nil {
		return err
	}
	// Print the versions of the plugin and of the Go toolchain it was built with.
	if err := runCommand(ctx, "", nil, plugin, "--version"); err != nil {
		return err
	}
	if err := runCommand(ctx, "", nil, "go", "version", plugin); err != nil {
		return err
	}

	generatedDir := filepath.Join(workDir, "generated")
	if err := os.Mkdir(generatedDir, 0o755); err != nil {
		return err
	}
	for _, protoFile := range protoFiles {
		name := filepath.Base(protoFile)
		fmt.Printf("Processing %s...\n", name)
		// The files import each other as "proto/<name>.proto", which is
		// resolved relative to the tink-go directory.
		err := runCommand(ctx, "proto", nil, protoc, "--plugin=protoc-gen-go="+plugin, "--proto_path=.",
			"-I"+tinkGoDir, "--go_out=paths=source_relative:"+generatedDir, name)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(generatedDir, strings.TrimSuffix(name, ".proto")+".pb.go"))
		if err != nil {
			return err
		}
		dst := filepath.Join(outDir, outputPath(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("Generated %d files in %s\n", len(protoFiles), outDir)
	return nil
}

// outputPath returns the path of the file generated from the given .proto
// file, relative to the output directory.
func outputPath(protoFile string) string {
	name := strings.TrimSuffix(protoFile, ".proto")
	return filepath.Join(name+"_go_proto", name+".pb.go")
}

// parseToolchain returns the argument of the toolchain directive of a go.mod
// file, for example "go1.26.10".
func parseToolchain(goMod []byte) (string, error) {
	for _, line := range strings.Split(string(goMod), "\n") {
		line, _, _ = strings.Cut(line, "//")
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "toolchain" {
			return fields[1], nil
		}
	}
	return "", errors.New("go.mod has no toolchain directive to build protoc-gen-go with")
}

// installProtoc downloads the pinned protoc release, verifies its checksum and
// writes the protoc binary to dst.
func installProtoc(ctx context.Context, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protocURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: unexpected HTTP status %s", protocURL, resp.Status)
	}
	archive, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := verifyChecksum(archive, protocSHA256); err != nil {
		return fmt.Errorf("%s: %v", protocURL, err)
	}
	protoc, err := extractProtoc(archive)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, protoc, 0o755)
}

// verifyChecksum fails if the hex-encoded SHA256 checksum of data is not want.
func verifyChecksum(data []byte, want string) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("SHA256 checksum mismatch: got %s, want %s", got, want)
	}
	return nil
}

// extractProtoc returns the contents of bin/protoc in the given zip archive.
//
// The standard archive/zip package is sufficient here: the archive has passed
// the pinned SHA256 check, and only the single entry bin/protoc is read, into
// a path that this tool chooses. No file name from the archive is used to
// write to disk.
func extractProtoc(archive []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	f, err := r.Open("bin/protoc")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// runCommand runs a command in dir, with env added to the environment, and
// waits for it. If ctx is cancelled, the command is interrupted, and killed if
// it has not exited after a grace period.
func runCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s %s: %v", name, strings.Join(args, " "), err)
	}
	return nil
}
