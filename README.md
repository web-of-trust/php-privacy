PHP Privacy - The OpenPGP library in PHP language
=================================================
PHP Privacy is an implementation of the OpenPGP standard in PHP language.
It implements [RFC4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC5581](https://www.rfc-editor.org/rfc/rfc5581), [RFC6637](https://www.rfc-editor.org/rfc/rfc6637),
parts of [RFC4880bis](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis).

## Requirement
* PHP 8.1.x or later,
* [phpseclib](https://github.com/phpseclib/phpseclib) library provides cryptography algorithms,
* (optional) PHPUnit to run tests,

## Features
* Support data signing & encryption.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)),
  [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm),
  [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption),
  [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm),
  [EdDSA](https://en.wikipedia.org/wiki/EdDSA)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
* Support symmetric ciphers: TripleDES, IDEA, CAST5, Blowfish, Twofish,
  [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard),
  [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher)).
* Support AEAD algorithms: [EAX](https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf), [OCB](https://tools.ietf.org/html/rfc7253), [GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
* Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224.
* Support compression algorithms: Zip, Zlib, BZip2.
* Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secP256k1, secP384r1, secP521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [curve25519](https://www.rfc-editor.org/rfc/rfc7748), [ed25519](https://www.rfc-editor.org/rfc/rfc8032),
  [prime256v1](https://www.secg.org/sec2-v2.pdf).

## Installation
Via [Composer](https://getcomposer.org)
```bash
$ composer require php-privacy/openpgp
```
or just add it to your `composer.json` file directly.
```javascript
{
    "require": {
        "php-privacy/openpgp": "*"
    }
}
```

## Basic usage of PHP Privacy
Sign and verify cleartext message
```php
<?php declare(strict_types=1);

require_once 'vendor/autoload.php';

use OpenPGP\OpenPGP;

$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
$passphrase = 'Your passphrase';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, $passphrase);
$cleartextMessage = OpenPGP::createCleartextMessage('Hello, PHP Privacy!');
$signedMessage = $cleartextMessage->sign([$privateKey]);
$verifications = $signedMessage->verify([$publicKey]);
```

## Licensing
[BSD 3-Clause](LICENSE)

    For the full copyright and license information, please view the LICENSE
    file that was distributed with this source code.
