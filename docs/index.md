PHP Privacy introduction
========================

## Introduction
`php-privacy/openpgp` is an implementation of the OpenPGP standard in PHP language.
It implements [RFC4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC6637](https://www.rfc-editor.org/rfc/rfc6637),
parts of [RFC4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis).

## Features
1. Support data signing & encryption.
2. Support key management: key generation, key reading, key decryption.
3. Support public-key algorithms: [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)),
  [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm),
  [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption),
  [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm),
  [EdDSA](https://en.wikipedia.org/wiki/EdDSA)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
4. Support symmetric ciphers: TripleDES, IDEA, CAST5, Blowfish, Twofish,
  [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard),
  [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher)).
5. Support AEAD ciphers: [EAX](https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf), [OCB](https://tools.ietf.org/html/rfc7253), [GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
6. Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224, SHA3-256, SHA3-512.
7. Support compression algorithms: Zip, Zlib, BZip2.
8. Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secp256r1, secp384r1, secp521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [Curve25519, Curve448](https://www.rfc-editor.org/rfc/rfc7748), [Ed25519, Ed448](https://www.rfc-editor.org/rfc/rfc8032).

## Documentation
1. [Installation](installation.md)
2. [Key managerment](key-managerment.md)
3. [Cleartext signing](cleartext-singing.md)
3. [Message signing & encryption](message-sign-encrypt.md)
