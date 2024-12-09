<?php declare(strict_types=1);

require_once dirname(__DIR__) . "/vendor/autoload.php";

use OpenPGP\OpenPGP;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\KeyType;

$userIDs = [
    "Nguyen Van Nguyen <nguyennv1981@gmail.com>",
    "Nguyen Van Nguyen <nguyennv@iwayvietnam.com>",
];
$passphrase = Helper::generatePassword();
echo "Generate passphrase: {$passphrase}" . PHP_EOL;

echo "Generate RSA private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphrase, KeyType::Rsa);
echo $privateKey->armor() . PHP_EOL;

echo "Generate Ecc private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphrase, KeyType::Ecc);
echo $privateKey->armor() . PHP_EOL;

echo "Generate Curve25519 private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphrase, KeyType::Curve25519);
echo $privateKey->armor() . PHP_EOL;

echo "Generate Curve448 private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphrase, KeyType::Curve448);
echo $privateKey->armor() . PHP_EOL;
