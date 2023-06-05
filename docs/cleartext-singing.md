Cleartext signing
=================

### Sign and verify cleartext
```php
$text = 'Hello PHP Privacy!';
$passphrase = 'secret stuff';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, $passphrase);

$signedMessage = OpenPGP::signCleartext($text, [$privateKey]);
file_put_contents('signedMessage.asc', $signedMessage->armor());

$verifications = OpenPGP::verify($signedMessage->armor(), [$publicKey]);
```

### Detached sign and verify cleartext
```php
$text = 'Hello PHP Privacy!';
$passphrase = 'secret stuff';
$armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
$armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

$publicKey = OpenPGP::readPublicKey($armoredPublicKey);
$privateKey = OpenPGP::decryptPrivateKey($armoredPrivateKey, $passphrase);

$signature = OpenPGP::signDetachedCleartext($text, [$privateKey]);
file_put_contents('signature.asc', $signature->armor());

$verifications = OpenPGP::verifyDetached($text, $signature->armor(), [$publicKey]);
```
