PHP Privacy installation
========================

## Requirement
* PHP 8.1.x or later,
* [phpseclib](https://github.com/phpseclib/phpseclib) library provides cryptography algorithms,
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
        "php-privacy/openpgp": "*"
    }
}
```

## Configuration

```php
<?php declare(strict_types=1);

require_once 'vendor/autoload.php';

use OpenPGP\Common\Config;

// Set preferred hash algorithm.
Config::setPreferredHash($hash);

// Set preferred symmetric algorithm.
Config::setPreferredSymmetric($symmetric);

// Set preferred compression algorithm.
Config::setPreferredCompression($compression);

// Set a logger.
Config::setLogger($logger);
```
