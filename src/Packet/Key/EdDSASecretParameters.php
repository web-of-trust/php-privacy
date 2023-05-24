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
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
};
use OpenPGP\Type\SignableParametersInterface;

/**
 * EdDSA secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class EdDSASecretParameters extends ECSecretParameters implements SignableParametersInterface
{
    const SIGNATURE_LENGTH = 64;

    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param EdDSAPublicParameters $publicParams
     * @param PrivateKey $privateKey
     * @return self
     */
    public function __construct(
        BigInteger $d,
        EdDSAPublicParameters $publicParams,
        ?PrivateKey $privateKey = null
    )
    {
        parent::__construct($d, $publicParams, $privateKey);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param EdDSAPublicParameters $publicParams
     * @return self
     */
    public static function fromBytes(
        string $bytes, EdDSAPublicParameters $publicParams
    ): self
    {
        return new self(
            Helper::readMPI($bytes),
            $publicParams
        );
    }

    /**
     * Generates parameters by using EC create key
     *
     * @param CurveOid $curve
     * @return self
     */
    public static function generate(CurveOid $curveOid): self
    {
        if ($curveOid === CurveOid::Ed25519) {
            $privateKey = EC::createKey($curveOid->name);
            $key = PKCS8::load($privateKey->toString('PKCS8'));
            return new self(
                Helper::bin2BigInt($key['secret']),
                new EdDSAPublicParameters(
                    ASN1::encodeOID($curveOid->value),
                    Helper::bin2BigInt(
                        "\x40" . $privateKey->getEncodedCoordinates()
                    ),
                    $privateKey->getPublicKey()
                ),
                $privateKey,
            );
        }
        else {
            throw new \UnexpectedValueException(
                "{$curveOid->name} is not supported for EdDSA key generation"
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->getPrivateKey()->sign(
            hash(strtolower($hash->name), $message, true)
        );
        $length = intval(self::SIGNATURE_LENGTH / 2);
        return implode([
            pack('n', $length * 8), // r bit length
            substr($signature, 0, $length), // r
            pack('n', $length * 8), // s bit length
            substr($signature, $length, $length), // s
        ]);
    }
}
