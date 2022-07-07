workspace(name = "tink_go_hcvault")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# -------------------------------------------------------------------------
# Protobuf.
# -------------------------------------------------------------------------
# proto_library, cc_proto_library and java_proto_library rules implicitly
# depend respectively on:
#   * @com_google_protobuf//:proto
#   * @com_google_protobuf//:cc_toolchain
#   * @com_google_protobuf//:java_toolchain
# This statement defines the @com_google_protobuf repo.
# Release from 2021-06-08.
http_archive(
    name = "com_google_protobuf",
    sha256 = "6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42",
    strip_prefix = "protobuf-3.19.3",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# -------------------------------------------------------------------------
# Bazel rules for Go.
# -------------------------------------------------------------------------
# Release from 2022-03-21
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "f2dcd210c7095febe54b804bb1cd3a58fe8435a909db2ec04e31542631cf715c",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
    ],
)

# -------------------------------------------------------------------------
# Bazel Gazelle.
# -------------------------------------------------------------------------
# Release from 2021-10-11.
http_archive(
    name = "bazel_gazelle",
    sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
# Tink Go Google Cloud KMS Deps.
load("//:deps.bzl", "tink_go_hcvault_dependencies")

# gazelle:repository_macro deps.bzl%tink_go_hcvault_dependencies
tink_go_hcvault_dependencies()

# TODO(b/213404399): Remove after Gazelle issue is fixed.
go_repository(
    name = "com_google_cloud_go_compute",
    importpath = "cloud.google.com/go/compute",
    sum = "h1:rSUBvAyVwNJ5uQCKNJFMwPtTvJkfN38b6Pvb9zZoqJ8=",
    version = "v0.1.0",
)

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.17.6",
)

gazelle_dependencies()
