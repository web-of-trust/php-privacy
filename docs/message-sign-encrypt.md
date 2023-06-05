Message signing & encryption
============================

### Encrypt and decrypt data with a password

```php
$text = 'Hello PHP Privacy!';
$password = 'secret stuff';

$encryptedMessage = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage($text), passwords: [$password]
);
file_put_contents('encryptedMessage.asc', $encryptedMessage->armor());

$decryptedMessage = OpenPGP::decrypt(
    $encryptedMessage, passwords: [$password]
);
echo $decryptedMessage->getLiteralData()->getData();
```

### Encrypt and decrypt data with PGP keys
Encryption will use the algorithm preferred by the public (encryption) key (defaults to aes128 for keys generated),
and decryption will use the algorithm used for encryption.

```php
$text = 'Hello PHP Privacy!';
$passphrase = 'secret stuff';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, $passphrase);

$encryptedMessage = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage($text), [$publicKey]
);
file_put_contents('encryptedMessage.asc', $encryptedMessage->armor());

$decryptedMessage = OpenPGP::decrypt(
    $encryptedMessage, [$privateKey]
);
echo $decryptedMessage->getLiteralData()->getData();
```

Sign message & encrypt with multiple public keys:

```php
$text = 'Hello PHP Privacy!';
$passphrase = 'secret stuff';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$publicKeys = array_map(static fn ($armored) => OpenPGP::readPublicKey($armored), $armoredPublicKeys);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, $passphrase);

$encryptedMessage = OpenPGP::encrypt(
    OpenPGP::createLiteralMessage($text), $publicKeys, signingKeys: [$privateKey]
);
file_put_contents('encryptedMessage.asc', $encryptedMessage->armor());

$decryptedMessage = OpenPGP::decrypt(
    $encryptedMessage, [$privateKey]
);
$verifications = $decryptedMessage->verify([$publicKey]);
echo $decryptedMessage->getLiteralData()->getData();
```
