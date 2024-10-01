<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\Ecc;
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\Crypt\Random;
use phpseclib3\File\ASN1;

/**
 * ECDH secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ECDHSecretKeyMaterial extends ECSecretKeyMaterial
{
    const CURVE25519_KEY_LENGTH = 32;

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial
    ): self {
        return new self(Helper::readMPI($bytes), $publicMaterial);
    }

    /**
     * Generate key material by using EC create key
     *
     * @param Ecc $curve
     * @return self
     */
    public static function generate(Ecc $curve): self
    {
        if ($curve !== Ecc::Ed25519) {
            if ($curve === Ecc::Curve25519) {
                do {
                    $secretKey = Random::string(self::CURVE25519_KEY_LENGTH);
                    // The highest bit must be 0 & the second highest bit must be 1
                    $secretKey[0] = ($secretKey[0] & "\x7f") | "\x40";
                    /// The lowest three bits must be 0
                    $secretKey[31] = $secretKey[31] & "\xf8";
                    $d = Helper::bin2BigInt($secretKey);
                } while (
                    $d->getLengthInBytes() !== self::CURVE25519_KEY_LENGTH
                );

                $privateKey = EC::loadPrivateKeyFormat(
                    "MontgomeryPrivate",
                    strrev($secretKey)
                );
                $q = Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates()
                );
            } else {
                $privateKey = EC::createKey($curve->name);
                $params = PKCS8::load($privateKey->toString("PKCS8"));
                $d = $params["dA"];
                $q = Helper::bin2BigInt($privateKey->getEncodedCoordinates());
            }
            return new self(
                $d,
                new ECDHPublicKeyMaterial(
                    ASN1::encodeOID($curve->value),
                    $q,
                    $curve->hashAlgorithm(),
                    $curve->symmetricAlgorithm(),
                    ECDHPublicKeyMaterial::DEFAULT_RESERVED,
                    $privateKey->getPublicKey()
                ),
                $privateKey
            );
        } else {
            throw new \InvalidArgumentException(
                "Curve {$curve->name} is not supported for ECDH key generation."
            );
        }
    }
}
