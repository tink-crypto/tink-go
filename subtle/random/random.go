// Copyright 2018 Google LLC
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

// Package random provides functions that generate random numbers or bytes.
package random

import (
	"crypto/rand"
	"encoding/binary"
)

func mustRand(b []byte) {
	_, err := rand.Read(b)
	if err != nil {
		panic(err) // out of randomness, should never happen
	}
}

// GetRandomBytes randomly generates n bytes.
func GetRandomBytes(n uint32) []byte {
	buf := make([]byte, n)
	mustRand(buf)
	return buf
}

// GetRandomUint32 randomly generates an unsigned 32-bit integer.
func GetRandomUint32() uint32 {
	var b [4]byte
	mustRand(b[:])
	return binary.BigEndian.Uint32(b[:])
}
