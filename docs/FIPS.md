# FIPS-140 compliance

Tink's Go implementation doesn't have its own FIPS-140 CMVP certification, but
in many cases it wraps FIPS-certified components of the Go standard library.
Some portions of this library work with the debug setting `GODEBUG=fips140=only`
enabled, which causes non-FIPS-compliant uses of the standard library
cryptographic module to return errors or panic.

## AEAD

AEAD runs in FIPS-140-enforcing mode with the following key templates:

- AES128CTRHMACSHA256
- AES128GCM
- AES128GCMNoPrefix
- AES245CTRHMACSHA256
- AES256GCM
- XAES256GCM160BitNonce
- XAES256GCM192BitNonce
