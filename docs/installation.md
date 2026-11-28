PHP Privacy installation
========================

## Requirement
* PHP 8.1.x or later,
* [phpseclib](https://github.com/phpseclib/phpseclib) library provides cryptography algorithms,
* [Argon2](https://github.com/P-H-C/phc-winner-argon2) for Argon2 string-to-key
* (optional) the `gmp` extension: it makes reading keys on Curve25519 (Ed25519, X25519) much faster, for example about 1.5 ms instead of 41 ms for an Ed25519 public key,
* (optional) PHPUnit to run tests,

## Installation
The recommended installation method is using [Composer](https://getcomposer.org)
```bash
$ composer require php-privacy/openpgp
```
or just add it to your `composer.json` file directly.
```javascript
{
    "require": {
        "php-privacy/openpgp": "^2.2"
    }
}
```

## Configuration
The settings are static and apply to the whole PHP process.
[Configuration](configuration.md) lists every setting with its default.

```php
<?php declare(strict_types=1);

require_once 'vendor/autoload.php';

use OpenPGP\Common\Config;

// Set preferred hash algorithm.
Config::setPreferredHash($hash);

// Set preferred symmetric algorithm.
Config::setPreferredSymmetric($symmetric);

// Set preferred AEAD algorithm.
Config::setPreferredAead($aead);

// Set preferred compression algorithm.
Config::setPreferredCompression($compression);

// Set AEAD protection.
Config::setAeadProtect($protect);

// Preset RFC9580.
Config::presetRFC9580();
```
