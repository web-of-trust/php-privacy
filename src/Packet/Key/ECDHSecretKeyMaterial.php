<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{Ecc, MontgomeryCurve};
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;

/**
 * ECDH secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ECDHSecretKeyMaterial extends ECSecretKeyMaterial
{
    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial,
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
                $secret = MontgomeryCurve::Curve25519->generateSecretKey();
                $d = Helper::bin2BigInt(strrev($secret));
                $privateKey = EC::loadPrivateKeyFormat(
                    "MontgomeryPrivate",
                    $secret,
                );
                $q = Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates(),
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
                    $curve->encodeOid(),
                    $q,
                    $curve->hashAlgorithm(),
                    $curve->symmetricAlgorithm(),
                    ECDHPublicKeyMaterial::DEFAULT_RESERVED,
                    $privateKey->getPublicKey(),
                ),
                $privateKey,
            );
        } else {
            throw new \InvalidArgumentException(
                "Curve {$curve->name} is not supported for ECDH key generation.",
            );
        }
    }
}
