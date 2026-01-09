This directory is a copy of the pre-v1 wycheproof test vectors
needed by tink-go's tests.

These are from github.com/c2sp/wycheproof's old testvectors directory
before it was deleted. They come from its git commit b51abcfb8daf (Go module
version v0.0.0-20250901140545-b51abcfb8daf).

If you'd like verification that this is an exact copy that hasn't been tampered
with, check for yourself with:

    $ git fetch https://github.com/c2sp/wycheproof
    $ (cd testutil/wycheproofv0 && for x in *.json; do sha256sum $x | awk '{print $1}'; git cat-file -p b51abcfb8daf:testvectors/$x | sha256sum | awk '{print $1}'; done) | uniq -c

and see that each hash starts with " 2 ", indicating that the hash of the
local file matches the hash of the file in the git repository at that commit.

The license (Apache 2.0) is in LICENSE, which is the same as tink-go
itself (in ../../LICENSE).

See https://github.com/tink-crypto/tink-go/issues/31 for background.
