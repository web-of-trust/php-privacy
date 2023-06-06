<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\Crypt\Random;
use phpseclib3\File\ASN1;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;
use OpenPGP\Type\KeyMaterialInterface;

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
        string $bytes, KeyMaterialInterface $publicMaterial
    ): self
    {
        return new self(
            Helper::readMPI($bytes), $publicMaterial
        );
    }

    /**
     * Generate key material by using EC create key
     *
     * @param CurveOid $curveOid
     * @return self
     */
    public static function generate(CurveOid $curveOid): self
    {
        if ($curveOid !== CurveOid::Ed25519) {
            if ($curveOid === CurveOid::Curve25519) {
                $secretKey = Random::string(self::CURVE25519_KEY_LENGTH);
                $secretKey[0] = chr((ord($secretKey[0]) & 127) | 64);
                $secretKey[31] = chr(ord($secretKey[31]) & 248);
                $d = Helper::bin2BigInt($secretKey);

                $privateKey = EC::loadPrivateKeyFormat(
                    'MontgomeryPrivate', strrev($secretKey)
                );
                $q = Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates()
                );
            }
            else {
                $privateKey = EC::createKey($curveOid->name);
                $key = PKCS8::load($privateKey->toString('PKCS8'));
                $d = $key['dA'];
                $q = Helper::bin2BigInt(
                    $privateKey->getEncodedCoordinates()
                );
            }
            return new self(
                $d,
                new ECDHPublicKeyMaterial(
                    ASN1::encodeOID($curveOid->value),
                    $q,
                    $curveOid->hashAlgorithm(),
                    $curveOid->symmetricAlgorithm(),
                    ECDHPublicKeyMaterial::DEFAULT_RESERVED,
                    $privateKey->getPublicKey()
                ),
                $privateKey,
            );
        }
        else {
            throw new \UnexpectedValueException(
                "{$curveOid->name} is not supported for ECDH key generation."
            );
        }
    }
}
