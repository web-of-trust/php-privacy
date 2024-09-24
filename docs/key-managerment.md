Key managerment
===============

### Generate new key pair

Rsa key type:
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Rsa,
    rsaKeySize: RSAKeySize::Normal,
);
file_put_contents('privateKey.asc', $privateKey->armor());
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

Ecc key type (uses EcDsa/EdDsaLegacy algorithm for signing & Ecdh algorithm for encryption):
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Ecc,
    curve: CurveOid::Ed25519,
);
file_put_contents('privateKey.asc', $privateKey->armor());
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

Curve25519 key type (uses Ed25519 algorithm for signing & X25519 algorithm for encryption):
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Curve25519,
);
file_put_contents('privateKey.asc', $privateKey->armor());
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

Curve448 key type (uses Ed448 algorithm for signing & X448 algorithm for encryption):
```php
const PASSPHRASE = 'Your passphase';
const USER_ID = 'Your name <name@example.com>';
$privateKey = OpenPGP::generateKey(
    [USER_ID],
    PASSPHRASE,
    type: KeyType::Curve448,
);
file_put_contents('privateKey.asc', $privateKey->armor());
$publicKey = $privateKey->toPublic();
echo $publicKey; // '-----BEGIN PGP PUBLIC KEY BLOCK ... '
```

### Key reading

Key reading from armored key strings
```php
const PASSPHRASE = 'Your passphase';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, PASSPHRASE);
```

### Certify a key

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

### Revoke a key

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
