<?php declare(strict_types=1);

require_once dirname(__DIR__) . "/vendor/autoload.php";

use OpenPGP\OpenPGP;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;
use OpenPGP\Enum\KeyType;

$userIDs = [
    "Nguyen Van Nguyen <nguyennv1981@gmail.com>",
    "Nguyen Van Nguyen <nguyennv@iwayvietnam.com>",
];

$passphase = Helper::generatePassword();
echo "Generate passphase: {$passphase}" . PHP_EOL;

echo "Generate RSA private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphase, KeyType::Rsa);
echo $privateKey->armor() . PHP_EOL;

echo "Generate DSA private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphase, KeyType::Dsa);
echo $privateKey->armor() . PHP_EOL;

echo "Generate EcDSA private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphase, KeyType::Ecc, curve: CurveOid::Secp521r1);
echo $privateKey->armor() . PHP_EOL;

echo "Generate EdDSA private key" . PHP_EOL;
$privateKey = OpenPGP::generateKey($userIDs, $passphase, KeyType::Ecc, curve: CurveOid::Ed25519);
echo $privateKey->armor() . PHP_EOL;
