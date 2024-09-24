PHP Privacy - The OpenPGP library in PHP language
=================================================
PHP Privacy is an implementation of the OpenPGP standard in PHP language.
It implements [RFC9580](https://www.rfc-editor.org/rfc/rfc9580).

## Requirement
* PHP 8.1.x or later,
* [phpseclib](https://github.com/phpseclib/phpseclib) library provides cryptography algorithms,
* [Argon2](https://github.com/P-H-C/phc-winner-argon2) for Argon2 string-to-key,
* (optional) PHPUnit to run tests,

## Features
* Support data signing & encryption.
* Support key management: key generation, key reading, key decryption.
* Support public-key algorithms: [RSA](https://www.rfc-editor.org/rfc/rfc3447),
  [ECDSA](https://www.rfc-editor.org/rfc/rfc6979),
  [EdDSA](https://www.rfc-editor.org/rfc/rfc8032)
  and [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman).
* Support symmetric ciphers: Blowfish, Twofish,
  [AES](https://www.rfc-editor.org/rfc/rfc3394),
  [Camellia](https://www.rfc-editor.org/rfc/rfc3713).
* Support AEAD ciphers: [EAX](https://seclab.cs.ucdavis.edu/papers/eax.pdf),
  [OCB](https://tools.ietf.org/html/rfc7253),
  [GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf).
* Support hash algorithms: MD5, SHA-1, RIPEMD-160, SHA-256, SHA-384, SHA-512, SHA-224, SHA3-256, SHA3-512.
* Support compression algorithms: Zip, Zlib, BZip2.
* Support [ECC](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) curves:
  [secp256r1, secp384r1, secp521r1](https://www.rfc-editor.org/rfc/rfc6090),
  [brainpoolP256r1, brainpoolP384r1, brainpoolP512r1](https://www.rfc-editor.org/rfc/rfc5639),
  [Curve25519, Curve448](https://www.rfc-editor.org/rfc/rfc7748),
  [Ed25519, Ed448](https://www.rfc-editor.org/rfc/rfc8032).
* Support public-key algorithms & symmetric ciphers for signature verification & message decryption
  (backward compatibility): DSA, ElGamal, TripleDES, IDEA, CAST5

## Installation
Via [Composer](https://getcomposer.org)
```bash
$ composer require php-privacy/openpgp
```
or just add it to your `composer.json` file directly.
```javascript
{
    "require": {
        "php-privacy/openpgp": "^2.0"
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
