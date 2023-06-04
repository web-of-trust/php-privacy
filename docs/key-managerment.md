Key managerment
===============

## Generate new key pair

Rsa key type:
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Rsa,
    rsaKeySize: RSAKeySize::S4096,
);
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

Dsa key type (uses DSA algorithm for signing & ElGamal algorithm for encryption):
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Dsa,
    dhKeySize: RSAKeySize::L2048_N224,
);
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

Ecc key type (uses ECDSA/EdDSA algorithm for signing & ECDH algorithm for encryption):
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Ecc,
    curve: CurveInfo::Ed25519,
);
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

## Key reading

Key reading from armored key strings
```php
const PASSPHRASE = 'Your passphase';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, PASSPHRASE);
```

## Certify a key

Certify a key by using the private key:
```php
const PASSPHRASE = 'Your passphase';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, PASSPHRASE);

$certifiedKey = $privateKey->certifyKey($publicKey);
$certifiedKey->isCertified($privateKey->toPublic());
echo $certifiedKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

## Revoke a key

Revoke a key by using the private key:
```php
const PASSPHRASE = 'Your passphase';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, PASSPHRASE);

$revokedKey = $privateKey->revokeKey($publicKey);
$revokedKey->isRevoked($privateKey->toPublic());
echo $revokedKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```
