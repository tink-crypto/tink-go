// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aesgcm

import (
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/key"
)

// primitiveConstructor creates a [subtle.AESGCM] from a [key.Key].
//
// The key must be of type [aesgcm.Key].
func primitiveConstructor(k key.Key) (any, error) {
	that, ok := k.(*Key)
	if !ok {
		return nil, fmt.Errorf("key is of type %T; needed *Key", k)
	}
	// Key by design ensures that the key size is
	if that.parameters.IVSizeInBytes() != subtle.AESGCMIVSize {
		return nil, fmt.Errorf("unsupported IV size: got %v, want %v", that.parameters.IVSizeInBytes(), subtle.AESGCMIVSize)
	}
	if that.parameters.TagSizeInBytes() != subtle.AESGCMTagSize {
		return nil, fmt.Errorf("unsupported tag size: got %v, want %v", that.parameters.TagSizeInBytes(), subtle.AESGCMTagSize)
	}
	return subtle.NewAESGCM(that.KeyBytes().Data(insecuresecretdataaccess.Token{}))
}
