<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;

/**
 * ECDH secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ECDHSecretParameters extends ECSecretParameters
{
    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param ECDHPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        BigInteger $d,
        ECDHPublicParameters $publicParams,
        ?PrivateKey $privateKey = null
    )
    {
        parent::__construct($d, $publicParams, $privateKey);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param ECDHPublicParameters $publicParams
     * @return ECDHSecretParameters
     */
    public static function fromBytes(
        string $bytes, ECDHPublicParameters $publicParams
    ): ECDHSecretParameters
    {
        return new ECDHSecretParameters(
            Helper::readMPI($bytes), $publicParams
        );
    }

    /**
     * Generates parameters by using EC create key
     *
     * @param CurveOid $curveOid
     * @return ECDHSecretParameters
     */
    public static function generate(CurveOid $curveOid): ECDHSecretParameters
    {
        if ($curveOid !== CurveOid::Ed25519) {
            $privateKey = EC::createKey($curveOid->name);
            if ($curveOid === CurveOid::Curve25519) {
                $d = Helper::bin2BigInt(
                    strrev($privateKey->toString('MontgomeryPrivate'))
                );
                $q = Helper::bin2BigInt(
                    "\x40" . $privateKey->getEncodedCoordinates()
                );
            }
            else {
                $key = PKCS8::load($privateKey->toString('PKCS8'));
                $d = $key['dA'];
                $q = Helper::bin2BigInt($privateKey->getEncodedCoordinates());
            }
            return new ECDHSecretParameters(
                $d,
                new ECDHPublicParameters(
                    ASN1::encodeOID($curveOid->value),
                    $q,
                    $curveOid->hashAlgorithm(),
                    $curveOid->symmetricAlgorithm(),
                    ECDHPublicParameters::DEFAULT_RESERVED,
                    $privateKey->getPublicKey()
                ),
                $privateKey,
            );
        }
        else {
            throw new \UnexpectedValueException(
                "{$curveOid->name} is not supported for ECDH key generation"
            );
        }
    }
}
