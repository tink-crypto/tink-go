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
//
////////////////////////////////////////////////////////////////////////////////

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v3.21.12
// source: hmac_prf.proto

package hmac_prf_go_proto

import (
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type HmacPrfParams struct {
	state         protoimpl.MessageState   `protogen:"open.v1"`
	Hash          common_go_proto.HashType `protobuf:"varint,1,opt,name=hash,proto3,enum=google.crypto.tink.HashType" json:"hash,omitempty"` // HashType is an enum.
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HmacPrfParams) Reset() {
	*x = HmacPrfParams{}
	mi := &file_hmac_prf_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HmacPrfParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HmacPrfParams) ProtoMessage() {}

func (x *HmacPrfParams) ProtoReflect() protoreflect.Message {
	mi := &file_hmac_prf_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HmacPrfParams.ProtoReflect.Descriptor instead.
func (*HmacPrfParams) Descriptor() ([]byte, []int) {
	return file_hmac_prf_proto_rawDescGZIP(), []int{0}
}

func (x *HmacPrfParams) GetHash() common_go_proto.HashType {
	if x != nil {
		return x.Hash
	}
	return common_go_proto.HashType(0)
}

// key_type: type.googleapis.com/google.crypto.tink.HmacPrfKey
type HmacPrfKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       uint32                 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Params        *HmacPrfParams         `protobuf:"bytes,2,opt,name=params,proto3" json:"params,omitempty"`
	KeyValue      []byte                 `protobuf:"bytes,3,opt,name=key_value,json=keyValue,proto3" json:"key_value,omitempty"` // Placeholder for ctype and debug_redact.
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HmacPrfKey) Reset() {
	*x = HmacPrfKey{}
	mi := &file_hmac_prf_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HmacPrfKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HmacPrfKey) ProtoMessage() {}

func (x *HmacPrfKey) ProtoReflect() protoreflect.Message {
	mi := &file_hmac_prf_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HmacPrfKey.ProtoReflect.Descriptor instead.
func (*HmacPrfKey) Descriptor() ([]byte, []int) {
	return file_hmac_prf_proto_rawDescGZIP(), []int{1}
}

func (x *HmacPrfKey) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *HmacPrfKey) GetParams() *HmacPrfParams {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *HmacPrfKey) GetKeyValue() []byte {
	if x != nil {
		return x.KeyValue
	}
	return nil
}

type HmacPrfKeyFormat struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Params        *HmacPrfParams         `protobuf:"bytes,1,opt,name=params,proto3" json:"params,omitempty"`
	KeySize       uint32                 `protobuf:"varint,2,opt,name=key_size,json=keySize,proto3" json:"key_size,omitempty"`
	Version       uint32                 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HmacPrfKeyFormat) Reset() {
	*x = HmacPrfKeyFormat{}
	mi := &file_hmac_prf_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HmacPrfKeyFormat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HmacPrfKeyFormat) ProtoMessage() {}

func (x *HmacPrfKeyFormat) ProtoReflect() protoreflect.Message {
	mi := &file_hmac_prf_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HmacPrfKeyFormat.ProtoReflect.Descriptor instead.
func (*HmacPrfKeyFormat) Descriptor() ([]byte, []int) {
	return file_hmac_prf_proto_rawDescGZIP(), []int{2}
}

func (x *HmacPrfKeyFormat) GetParams() *HmacPrfParams {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *HmacPrfKeyFormat) GetKeySize() uint32 {
	if x != nil {
		return x.KeySize
	}
	return 0
}

func (x *HmacPrfKeyFormat) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

var File_hmac_prf_proto protoreflect.FileDescriptor

const file_hmac_prf_proto_rawDesc = "" +
	"\n" +
	"\x0ehmac_prf.proto\x12\x12google.crypto.tink\x1a\x12proto/common.proto\"A\n" +
	"\rHmacPrfParams\x120\n" +
	"\x04hash\x18\x01 \x01(\x0e2\x1c.google.crypto.tink.HashTypeR\x04hash\"~\n" +
	"\n" +
	"HmacPrfKey\x12\x18\n" +
	"\aversion\x18\x01 \x01(\rR\aversion\x129\n" +
	"\x06params\x18\x02 \x01(\v2!.google.crypto.tink.HmacPrfParamsR\x06params\x12\x1b\n" +
	"\tkey_value\x18\x03 \x01(\fR\bkeyValue\"\x82\x01\n" +
	"\x10HmacPrfKeyFormat\x129\n" +
	"\x06params\x18\x01 \x01(\v2!.google.crypto.tink.HmacPrfParamsR\x06params\x12\x19\n" +
	"\bkey_size\x18\x02 \x01(\rR\akeySize\x12\x18\n" +
	"\aversion\x18\x03 \x01(\rR\aversionB[\n" +
	"\x1ccom.google.crypto.tink.protoP\x01Z9github.com/tink-crypto/tink-go/v2/proto/hmac_prf_go_protob\x06proto3"

var (
	file_hmac_prf_proto_rawDescOnce sync.Once
	file_hmac_prf_proto_rawDescData []byte
)

func file_hmac_prf_proto_rawDescGZIP() []byte {
	file_hmac_prf_proto_rawDescOnce.Do(func() {
		file_hmac_prf_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_hmac_prf_proto_rawDesc), len(file_hmac_prf_proto_rawDesc)))
	})
	return file_hmac_prf_proto_rawDescData
}

var file_hmac_prf_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_hmac_prf_proto_goTypes = []any{
	(*HmacPrfParams)(nil),         // 0: google.crypto.tink.HmacPrfParams
	(*HmacPrfKey)(nil),            // 1: google.crypto.tink.HmacPrfKey
	(*HmacPrfKeyFormat)(nil),      // 2: google.crypto.tink.HmacPrfKeyFormat
	(common_go_proto.HashType)(0), // 3: google.crypto.tink.HashType
}
var file_hmac_prf_proto_depIdxs = []int32{
	3, // 0: google.crypto.tink.HmacPrfParams.hash:type_name -> google.crypto.tink.HashType
	0, // 1: google.crypto.tink.HmacPrfKey.params:type_name -> google.crypto.tink.HmacPrfParams
	0, // 2: google.crypto.tink.HmacPrfKeyFormat.params:type_name -> google.crypto.tink.HmacPrfParams
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_hmac_prf_proto_init() }
func file_hmac_prf_proto_init() {
	if File_hmac_prf_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_hmac_prf_proto_rawDesc), len(file_hmac_prf_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_hmac_prf_proto_goTypes,
		DependencyIndexes: file_hmac_prf_proto_depIdxs,
		MessageInfos:      file_hmac_prf_proto_msgTypes,
	}.Build()
	File_hmac_prf_proto = out.File
	file_hmac_prf_proto_goTypes = nil
	file_hmac_prf_proto_depIdxs = nil
}
