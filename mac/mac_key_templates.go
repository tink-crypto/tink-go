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

package mac

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/tinkerror"
	cmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplate for MAC.

// HMACSHA256Tag128KeyTemplate is a KeyTemplate that generates a HMAC key with the following parameters:
//   - Key size: 32 bytes
//   - Tag size: 16 bytes
//   - Hash function: SHA256
func HMACSHA256Tag128KeyTemplate() *tinkpb.KeyTemplate {
	return createHMACKeyTemplate(32, 16, commonpb.HashType_SHA256)
}

// HMACSHA256Tag256KeyTemplate is a KeyTemplate that generates a HMAC key with the following parameters:
//   - Key size: 32 bytes
//   - Tag size: 32 bytes
//   - Hash function: SHA256
func HMACSHA256Tag256KeyTemplate() *tinkpb.KeyTemplate {
	return createHMACKeyTemplate(32, 32, commonpb.HashType_SHA256)
}

// HMACSHA512Tag256KeyTemplate is a KeyTemplate that generates a HMAC key with the following parameters:
//   - Key size: 64 bytes
//   - Tag size: 32 bytes
//   - Hash function: SHA512
func HMACSHA512Tag256KeyTemplate() *tinkpb.KeyTemplate {
	return createHMACKeyTemplate(64, 32, commonpb.HashType_SHA512)
}

// HMACSHA512Tag512KeyTemplate is a KeyTemplate that generates a HMAC key with the following parameters:
//   - Key size: 64 bytes
//   - Tag size: 64 bytes
//   - Hash function: SHA512
func HMACSHA512Tag512KeyTemplate() *tinkpb.KeyTemplate {
	return createHMACKeyTemplate(64, 64, commonpb.HashType_SHA512)
}

// AESCMACTag128KeyTemplate is a KeyTemplate that generates a AES-CMAC key with the following parameters:
//   - Key size: 32 bytes
//   - Tag size: 16 bytes
func AESCMACTag128KeyTemplate() *tinkpb.KeyTemplate {
	return createCMACKeyTemplate(32, 16)
}

// createHMACKeyTemplate creates a new KeyTemplate for HMAC using the given parameters.
func createHMACKeyTemplate(keySize, tagSize uint32, hashType commonpb.HashType) *tinkpb.KeyTemplate {
	params := hmacpb.HmacParams{
		Hash:    hashType,
		TagSize: tagSize,
	}
	format := hmacpb.HmacKeyFormat{
		Params:  &params,
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.HmacKey",
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

// createCMACKeyTemplate creates a new KeyTemplate for CMAC using the given parameters.
func createCMACKeyTemplate(keySize uint32, tagSize uint32) *tinkpb.KeyTemplate {
	params := cmacpb.AesCmacParams{
		TagSize: tagSize,
	}
	format := cmacpb.AesCmacKeyFormat{
		Params:  &params,
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacKey",
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}
