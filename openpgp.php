<?php declare(strict_types=1);

require_once 'vendor/autoload.php';

use OpenPGP\OpenPGP;
use OpenPGP\Common\Armor;
use OpenPGP\Common\Argon2S2K;
use OpenPGP\Enum\{
    CurveOid,
    KeyType,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Cryptor\Mac\CMac;
use OpenPGP\Cryptor\Aead\EAX;
use OpenPGP\Cryptor\Aead\OCB;
use OpenPGP\Cryptor\Aead\GCM;
use OpenPGP\Packet\AeadEncryptedData;
use OpenPGP\Packet\PacketList;
use OpenPGP\Message\EncryptedMessage;
use OpenPGP\Key\PrivateKey;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\MontgomeryPrivate;
use phpseclib3\Crypt\EC\Formats\Keys\MontgomeryPublic;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\Crypt\Random;
use Symfony\Component\Process;

$privateKey = EC::createKey('Curve448');
$privateKey = EC::createKey('Curve25519');
$publicKey = EC::loadPublicKeyFormat(
    'MontgomeryPublic', $privateKey->getEncodedCoordinates()
);
var_dump($privateKey->getEncodedCoordinates());
var_dump($publicKey->getEncodedCoordinates());
var_dump($publicKey->getCurve());
exit;

$password = 'password';

$finder = new Process\ExecutableFinder();
if (!empty($path = $finder->find('argon2'))) {
    // $salt = 'lVLtqeMhsXMTgZB7';
    $salt = Random::string(Argon2S2K::SALT_LENGTH);
    $process = new Process\Process([
        $path, $salt, '-id', '-r',
        '-t', '3',
        '-p', '4',
        '-m', '16',
        '-l', '16',
    ]);
    $process->setInput($password);
    $process->run();
    if (!$process->isSuccessful()) {
        throw new Process\Exception\ProcessFailedException($process);
    }
    echo $process->getOutput();
}
exit;

$salt = Random::string(Argon2S2K::SALT_LENGTH);
var_dump(hash_algos());
var_dump(hash('SHA3-512', $password, true));
exit;
$salt = hex2bin('3c231fac71d107aa8e274fa3fa4ff914');
$hash = hex2bin('8b77c734c5ab3aaec00d327b8a9871e029a55372b5c4807cec2f9dbcbe70f485');

$salt = Random::string(Argon2S2K::SALT_LENGTH);
echo bin2hex($salt);
echo "\n";
echo base64_encode($salt);
echo "\n";
exit;

$salt = Random::string(Argon2S2K::SALT_LENGTH);
$s2k = new Argon2S2K($salt, 4, 3, 16);
echo bin2hex($s2k->produceKey($password, 24));
exit;
echo 'Sodium argon2id hash: ' . sodium_crypto_pwhash_str(
    $password,
    SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
    SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
);
echo "\n";

echo 'Argon2id hash: ' . password_hash($password, PASSWORD_ARGON2ID, [
    // 'time_cost' => 4,
    // 'memory_cost' => 65536,
]);
echo "\n";
exit;

$salt = '8d2d90235f00d3403af0beb1404ba5fb';
$opslimit = 4;
$memlimit = 2 << (16 + 9);
$hash = sodium_crypto_pwhash(
    16,
    $password,
    hex2bin($salt),
    $opslimit,
    $memlimit,
    SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
);
var_dump($hash);
exit;

echo 2 << (20 + 9);
echo "\n";

echo SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;
echo PASSWORD_ARGON2_DEFAULT_THREADS;
exit;
echo sodium_crypto_pwhash_str(
    $password,
    $opslimit,
    $memlimit
);
exit;

$hash = password_hash('passphrase', PASSWORD_ARGON2ID, [
    'memory_cost' => 2 << (16 - 1),
    'time_cost' => 3,
    'threads' => 4,
]);
var_dump($hash);
exit;

$publicKey = OpenPGP::readPublicKey(
    file_get_contents('f144cbdd51778b792ec9639d265bb03c07d95808.asc')
);
var_dump($publicKey->isRevoked());
exit;

$publicKeys = OpenPGP::readPublicKeys(
    file_get_contents('Exported-public-keys.asc')
);
var_dump($publicKeys);
exit;

$string = "I should have really done some laundry tonight.";
$stream = fopen('data://text/plain;base64,' . base64_encode($string), 'r');
echo stream_get_contents($stream);
exit;

$curve25519PrivateKey = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEY9oJqhYJKwYBBAHaRw8BAQdAcrAI+d3gM1JUzLKt4gryZ1d5hIvh+1y2dPwe
rIu8lR3+BwMCGTKI1DNqriX/x7jBmfKFrmVSzzTi8wQJDRYtqRiYPH8onY2j8f89
cdkE3CED3Kg6kUe/OiOCPm+hv8pPhosSheIWviHkSVhG+gHfbaqiJbQkY3VydmUg
MjU1MTkgcGdwIGtleSA8dGVzdEBkdW1teS5jb20+iJMEExYKADsWIQRnKHzGN2dG
5oP9JGdWVOVU1y/PRwUCY9oJqgIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIX
gAAKCRBWVOVU1y/PRx2uAP4zIRB2iMIp462zFPmAqF7B3WU6HHIkqSPEwPc116uR
GgEA0PV36y7AD3gvCDMYNrm7PjHZnCkVd2KKzmP41rb5qwqciwRj2gmqEgorBgEE
AZdVAQUBAQdAu+XJbbfH0AUNvZDk6NY/+DRC8bw8on7UfLgFoLGPMnIDAQgH/gcD
AvUjbflbYbLL/+V2mROWuh2nkwvZ2AqyRALUEyXasHvXSpG+vQ/jjOuNTNr3bopn
JEAQlmSqKtnb3NdWFpV8JL8DGRrHYh7WVfVC9NbeRlSIeAQYFgoAIBYhBGcofMY3
Z0bmg/0kZ1ZU5VTXL89HBQJj2gmqAhsMAAoJEFZU5VTXL89HShcA/16DUh6HoVrt
+9w8wIhqHT7RYAp4dWbvnWiTkvwlKH48AP0evp/GwXZ1qVluXk6bib/P1T+Wr1FX
+XY9JZQsi81qCw==
=qDmh
-----END PGP PRIVATE KEY BLOCK-----
EOT;
$privateKey = PrivateKey::fromArmored($curve25519PrivateKey)->decrypt('password');
// echo $privateKey->getFingerprint(true);
$user = $privateKey->getUsers()[0];
var_dump($user->verify());

exit;
$encryptedMessageData = <<<EOT
-----BEGIN PGP MESSAGE-----

jD0FBwIDCPTU9TrcG/ef/xFWqji4GJrUyUl69Pv5jAx2Kqji9g4nBGu5RXlYoY/8
cTHw+kww2UtrXVkeUDQI1EwBBwIQtSJxPQCq1Mg7/Ashm2BQxiCRO1DtO6TN/+sy
58ZOoB5PVTW8IcABVZi/8mtZtqY02rYfTcXYiyVQP9Qx0gnqM1hCCQp/tZYX
=id4U
-----END PGP MESSAGE-----
EOT;

$encryptedMessage = EncryptedMessage::fromArmored($encryptedMessageData);
var_dump($encryptedMessage);
$decryptedMessage = $encryptedMessage->decrypt(passwords: ['password']);
var_dump($decryptedMessage);exit;

exit;

$key = hex2bin('86f1efb86952329f24acd3bfd0e5346d');
$iv = hex2bin('b732379f73c4928de25facfe6517ec10');
$bytes = hex2bin('0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476');

$aedp = AeadEncryptedData::fromBytes($bytes);
$aedp = $aedp->decrypt($key);
$literalData = $aedp->getPacketList()->offsetGet(0);
var_dump($literalData);
exit;

$gcm = new GCM(Random::string(16));
$pt = Random::string(40);
$nonce = Random::string(12);
$adata = Random::string(10);
$ciphertext = $gcm->encrypt(
    $pt,
    $nonce,
    $adata
);
var_dump(bin2hex($ciphertext));

$plaintext = $gcm->encrypt(
    $ciphertext,
    $nonce,
    $adata
);
var_dump(bin2hex($pt));
var_dump(bin2hex($plaintext));
exit;

$ocb = new OCB(hex2bin('000102030405060708090A0B0C0D0E0F'));
$ciphertext = $ocb->encrypt(
    hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627'),
    hex2bin('bbaa9988776655443322110d'),
    hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627')
);
var_dump(bin2hex($ciphertext));

$plaintext = $ocb->decrypt(
    hex2bin('d5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7aed07ba06a4a69483a7035490c5769e60'),
    hex2bin('bbaa9988776655443322110d'),
    hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627')
);

var_dump(bin2hex($plaintext));
exit;

$eax = new EAX(hex2bin('7c77d6e813bed5ac98baa417477a2e7d'));
$ciphertext = $eax->encrypt(
    hex2bin('8b0a79306c9ce7ed99dae4f87f8dd61636'),
    hex2bin('1a8c98dcd73d38393b2bf1569deefc19'),
    hex2bin('65d2017990d62528')
);
var_dump(bin2hex($ciphertext));

$plaintext = $eax->decrypt(
    hex2bin('02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2'),
    hex2bin('1a8c98dcd73d38393b2bf1569deefc19'),
    hex2bin('65d2017990d62528')
);

var_dump(bin2hex($plaintext));
exit;

// https://artjomb.github.io/cryptojs-extension/
$cmac = new CMac(SymmetricAlgorithm::Aes128);
$output = $cmac->generate(
    hex2bin('02083e3979da014812f59f11d52630da30'),
    hex2bin('7c77d6e813bed5ac98baa417477a2e7d')
);
var_dump(bin2hex($output));

$output = $cmac->generate(
    hex2bin('6bc1bee22e409f96e93d7e117393172a'),
    hex2bin('2b7e151628aed2a6abf7158809cf4f3c')
);
var_dump(bin2hex($output));

$output = $cmac->generate(
    hex2bin('6bc1bee22e409f96e93d7e117393172a'),
    hex2bin('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
);
var_dump(bin2hex($output));
exit;

for ($i = 0; $i < 100; $i++) { 
}
$privateKey = OpenPGP::generateKey(
    ['Nguyen Van Nguyen <nguyennv@gmail.com>'],
    'password',
    KeyType::Ecc,
    curve: CurveOid::Ed25519
);
$privateKey = OpenPGP::decryptPrivateKey($privateKey->armor(), 'password');
$privateKey->verify();
echo $privateKey;
echo PHP_EOL;
// echo $privateKey->encrypt('passphrase');
file_put_contents('privateKey.asc', $privateKey->armor());
