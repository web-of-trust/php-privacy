PHP Privacy introduction
========================

## Introduction
`php-privacy/openpgp` is an implementation of the OpenPGP standard in PHP language.
It implements [RFC9580](https://www.rfc-editor.org/rfc/rfc9580).

## Features
1. Support data signing & encryption.
2. Support key management: key generation, key reading, key decryption.
3. Support public-key algorithms: [RSA](https://www.rfc-editor.org/rfc/rfc3447),
  [ECDSA](https://www.rfc-editor.org/rfc/rfc6979),
  [EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
4. Support symmetric ciphers: Blowfish, Twofish,
  [AES](https://www.rfc-editor.org/rfc/rfc3394),
  [Camellia](https://www.rfc-editor.org/rfc/rfc3713).
5. Support AEAD ciphers: [EAX](https://seclab.cs.ucdavis.edu/papers/eax.pdf),
  [OCB](https://tools.ietf.org/html/rfc7253),
  [GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf).
6. Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224, SHA3-256, SHA3-512.
7. Support compression algorithms: Zip, Zlib, BZip2.
8. Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secp256r1, secp384r1, secp521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [Curve25519, Curve448](https://www.rfc-editor.org/rfc/rfc7748),
  [Ed25519, Ed448](https://www.rfc-editor.org/rfc/rfc8032).
9. Support public-key algorithms & symmetric ciphers for signature verification & message decryption
  (backward compatibility): DSA, ElGamal, TripleDES, IDEA, CAST5

## Documentation
1. [Installation](installation.md)
2. [Key managerment](key-managerment.md)
3. [Cleartext signing](cleartext-singing.md)
3. [Message signing & encryption](message-sign-encrypt.md)
