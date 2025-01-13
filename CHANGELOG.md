# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.0.0 - released 2023-06-06
- First major release

## 1.0.1 - released 2023-06-13
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.0.0...1.0.1)
- Re-format code by psalm recomendations

## 1.0.2 - released 2023-06-13
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.0.1...1.0.2)
- Validate subkey packet when decrypt private key
- Migrate phpunit XML configuration

## 1.0.3 - released 2023-06-15
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.0.2...1.0.3)
- Add S2K hash configuration

## 1.0.4 - released 2023-06-2
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.0.3...1.0.4)
- Refactor checksum computing of session key
- Refactor string to key

## 1.1.0 - released 2023-12-16
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.0.4...1.1.0)
- Support AEAD algorithms: EAX, OCB, GCM. 
- Supporp key and signature version 5.

## 1.1.1 - released 2024-01-17
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.0...1.1.1)
- Refactor user and subkey validate. 
- Refactor key material validate.

## 1.1.2 - released 2024-01-18
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.1...1.1.2)
- Fix ElGamal input validation.

## 1.1.3 - released 2024-03-05
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.2...1.1.3)
- Refactor comparisons & for loops.
- Remove EOL after chunk split base64 string.

## 1.1.4 - released 2024-03-18
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.3...1.1.4)
- Add OpenPGP readPublicKeys method.
- Add RevocationReasonTag parameter to revoke methods.

## 1.1.5 - released 2024-03-18
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.4...1.1.5)
- Refactor isRevoked methods.

## 1.1.6 - released 2024-03-22
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.5...1.1.6)
- Refactor get key strength of key packet.
- Pass preferred symmetric to secret key packet encrypt

## 1.1.7 - released 2024-03-27
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.6...1.1.7)
- Refactor OpenPGP revokeKey method.

## 1.1.8 - released 2024-08-27
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.7...1.1.8)
- Add checksum to none encrypted secret key packet.

## 1.1.9 - released 2024-09-06
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.8...1.1.9)
- Remove random prefix & MDC packet.
- Fix gcm encryptor.
- Add salt notation to signature.

## 1.1.10 - released 2024-09-09
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.9...1.1.10)
- Refactor cleartext signature framework.
- Add getSessionKey method to EncryptedMessage.

## 1.1.11 - released 2024-09-11
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.10...1.1.11)
- Fix partial packet reader.
- Fix AEAD Protected Data encrypt/decrypt.

## 1.1.12 - released 2024-09-12
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.11...1.1.12)
- Fix packet reader.
- Fix aead crypt.

## 1.1.13 - released 2024-09-13
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.12...1.1.13)
- Support partial body length.

## 1.1.14 - released 2024-09-18
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.13...1.1.14)
- Reverse order OPS packets.
- Change SALT_NOTATION
- Refactor ECDH session key cryptor contants
- Add build one-pass signature packet from signature packet

## 1.2.0 - released 2024-09-19
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.1.14...1.2.0)
- Support reading openpgp message & key from binary string.

## 1.2.1 - released 2024-09-25
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.2.0...1.2.1)
- Change VERSION const.
- Change SALT_NOTATION const.
- Fix armor text dash escape.

## 1.2.2 - released 2024-09-30
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.2.1...1.2.2)
- Refactor code with phpactor.
- Add PHP Privacy Examples.

## 1.2.3 - released 2024-10-10
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.2.2...1.2.3)
- Refactor package partial encode.

## 1.2.4 - released 2024-10-22
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.2.3...1.2.4)
- Disable symmetric padding.

## 1.2.5 - released 2024-11-05
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/1.2.4...1.2.5)
- Refactor decode public key packet from bytes.
- Refactor decode secret key packet from bytes.
- Refactor generate secret key packet.
- Refactor encrypt secret key packet.
- Refactor decrypt secret key packet.

## 2.0.0 - released 2024-10-01
- Release to major version 2

## 2.0.1 - released 2024-10-10
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.1...2.0.1)
- Refactor Montgomery Curve Enum
- Refactor generate Montgomery secret key
- Refactor package encode

## 2.0.2 - released 2024-10-22
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.1...2.0.2)
- Disable symmetric padding.

## 2.0.3 - released 2024-11-05
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.2...2.0.3)
- Refactor decode public key packet from bytes.
- Refactor decode secret key packet from bytes.
- Refactor generate secret key packet.
- Refactor encrypt secret key packet.
- Refactor decrypt secret key packet.
- Add key version enum.

## 2.0.4 - released 2024-11-16
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.3...2.0.4)
- Refactor AEAD crypt.

## 2.0.5 - released 2024-12-13
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.4...2.0.5)
- Fix calculate number of byte processed of AeadEncryptedData.

## 2.1.0 - released 2024-12-14
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.0.5...2.1.0)
- Add `generateSessionKey`, `encryptSessionKey`, `decryptSessionKey` methods to high level API.
- Refactor OpenPGP key classes.
- Add preset RFC enum: RFC4880, RFC9580
- Remove `useV6Key` config.

## 2.1.1 - released 2025-01-13
[Full Changelog](https://github.com/web-of-trust/php-privacy/compare/2.1.0...2.1.1)
- Unwrap compressed before compress.
- Fix compression argument passing to compress message.
