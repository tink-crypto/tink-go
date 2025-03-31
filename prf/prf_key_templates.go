// Copyright 2020 Google LLC
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

package prf

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/internal/tinkerror"
	cmacpb "github.com/tink-crypto/tink-go/v2/proto/aes_cmac_prf_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hkdfpb "github.com/tink-crypto/tink-go/v2/proto/hkdf_prf_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_prf_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplate for PRF.

// HMACSHA256PRFKeyTemplate is a KeyTemplate that generates an HMAC key with the following parameters:
//   - Key size: 32 bytes
//   - Hash function: SHA256
func HMACSHA256PRFKeyTemplate() *tinkpb.KeyTemplate {
	return createHMACPRFKeyTemplate(32, commonpb.HashType_SHA256)
}

// HMACSHA512PRFKeyTemplate is a KeyTemplate that generates an HMAC key with the following parameters:
//   - Key size: 64 bytes
//   - Hash function: SHA512
func HMACSHA512PRFKeyTemplate() *tinkpb.KeyTemplate {
	return createHMACPRFKeyTemplate(64, commonpb.HashType_SHA512)
}

// HKDFSHA256PRFKeyTemplate is a KeyTemplate that generates an HKDF key with the following parameters:
//   - Key size: 32 bytes
//   - Salt: empty
//   - Hash function: SHA256
func HKDFSHA256PRFKeyTemplate() *tinkpb.KeyTemplate {
	return createHKDFPRFKeyTemplate(32, commonpb.HashType_SHA256, make([]byte, 0))
}

// AESCMACPRFKeyTemplate is a KeyTemplate that generates a AES-CMAC key with the following parameters:
//   - Key size: 32 bytes
func AESCMACPRFKeyTemplate() *tinkpb.KeyTemplate {
	return createAESCMACPRFKeyTemplate(32)
}

// createHMACPRFKeyTemplate creates a new KeyTemplate for HMAC using the given parameters.
func createHMACPRFKeyTemplate(keySize uint32, hashType commonpb.HashType) *tinkpb.KeyTemplate {
	params := hmacpb.HmacPrfParams{
		Hash: hashType,
	}
	format := hmacpb.HmacPrfKeyFormat{
		Params:  &params,
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          hmacprfTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedFormat,
	}
}

// createHKDFPRFKeyTemplate creates a new KeyTemplate for HKDF using the given parameters.
func createHKDFPRFKeyTemplate(keySize uint32, hashType commonpb.HashType, salt []byte) *tinkpb.KeyTemplate {
	params := hkdfpb.HkdfPrfParams{
		Hash: hashType,
		Salt: salt,
	}
	format := hkdfpb.HkdfPrfKeyFormat{
		Params:  &params,
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.HkdfPrfKey",
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedFormat,
	}
}

// createAESCMACPRFKeyTemplate creates a new KeyTemplate for AES-CMAC using the given parameters.
func createAESCMACPRFKeyTemplate(keySize uint32) *tinkpb.KeyTemplate {
	format := cmacpb.AesCmacPrfKeyFormat{
		KeySize: keySize,
	}
	serializedFormat, err := proto.Marshal(&format)
	if err != nil {
		tinkerror.Fail(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          "type.googleapis.com/google.crypto.tink.AesCmacPrfKey",
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedFormat,
	}
}
