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
use phpseclib3\Crypt\EC\PublicKey;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;

use OpenPGP\Enum\CurveOid;

/**
 * EC public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class ECPublicParameters implements KeyParametersInterface
{
    private readonly CurveOid $curveOid;

    /**
     * phpseclib3 EC public key
     */
    private readonly PublicKey $publicKey;

    /**
     * Constructor
     *
     * @param string $oid
     * @param BigInteger $q
     * @param PublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly string $oid,
        private readonly BigInteger $q,
        ?PublicKey $publicKey = null
    )
    {
        $this->curveOid = CurveOid::from(ASN1::decodeOID($oid));
        if ($publicKey instanceof PublicKey) {
            $this->publicKey = $publicKey;
        }
        else {
            $format = 'PKCS8';
            $curve = $this->curveOid->getCurve();
            switch ($this->curveOid) {
                case CurveOid::Ed25519:
                    $key = PKCS8::savePublicKey(
                        $curve, PKCS8::extractPoint(
                            substr($q->toBytes(), 1), $curve
                        )
                    );
                    break;
                case CurveOid::Curve25519:
                    $key = substr($q->toBytes(), 1);
                    $format = 'MontgomeryPublic';
                    break;
                default:
                    $key = PKCS8::savePublicKey(
                        $curve, PKCS8::extractPoint("\x0" . $q->toBytes(), $curve)
                    );
                    break;
            }
            $this->publicKey = EC::loadFormat($format, $key);
        }
    }

    /**
     * Gets curve oid
     *
     * @return CurveOid
     */
    public function getCurveOid(): CurveOid
    {
        return $this->curveOid;
    }

    /**
     * Gets public key coordinates
     *
     * @return BigInteger
     */
    public function getQ(): BigInteger
    {
        return $this->q;
    }

    /**
     * Gets public key
     *
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicParams(): KeyParametersInterface
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            chr(strlen($this->oid)),
            $this->oid,
            pack('n', $this->q->getLength()),
            $this->q->toBytes(),
        ]);
    }
}
