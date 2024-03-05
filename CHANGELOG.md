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
