<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\CurveOid;
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib3\Crypt\Common\{
    AsymmetricKey,
    PublicKey,
};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PublicKey as ECPublicKey;
use phpseclib3\Crypt\EC\Formats\Keys\MontgomeryPublic;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;

/**
 * EC public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class ECPublicKeyMaterial implements KeyMaterialInterface
{
    private readonly CurveOid $curveOid;

    /**
     * phpseclib3 EC public key
     */
    protected readonly ECPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param string $oid
     * @param BigInteger $q
     * @param ECPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly string $oid,
        private readonly BigInteger $q,
        ?ECPublicKey $publicKey = null
    )
    {
        $this->curveOid = CurveOid::fromOid($oid);
        if ($publicKey instanceof ECPublicKey) {
            $this->publicKey = $publicKey;
        }
        else {
            $format = 'PKCS8';
            $curve = $this->curveOid->getCurve();
            switch ($this->curveOid) {
                case CurveOid::Curve25519:
                    $key = substr($q->toBytes(), 1);
                    $format = 'MontgomeryPublic';
                    break;
                default:
                    $point = ($this->curveOid === CurveOid::Ed25519) ?
                             substr($q->toBytes(), 1) : "\x00" . $q->toBytes();
                    $key = PKCS8::savePublicKey(
                        $curve,
                        PKCS8::extractPoint($point, $curve)
                    );
                    break;
            }
            $this->publicKey = EC::loadPublicKeyFormat($format, $key);
        }
    }

    /**
     * Get curve oid
     *
     * @return CurveOid
     */
    public function getCurveOid(): CurveOid
    {
        return $this->curveOid;
    }

    /**
     * Get public key coordinates
     *
     * @return BigInteger
     */
    public function getQ(): BigInteger
    {
        return $this->q;
    }

    /**
     * Get EC public key
     *
     * @return ECPublicKey
     */
    public function getECPublicKey(): ECPublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->publicKey->getLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAsymmetricKey(): AsymmetricKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        if ($this->curveOid === CurveOid::Curve25519) {
            return MontgomeryPublic::load(
                $this->publicKey->toString('MontgomeryPublic')
            );
        }
        else {
            return PKCS8::load($this->publicKey->toString('PKCS8'));
        }
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
    public function toBytes(): string
    {
        return implode([
            chr(strlen($this->oid)),
            $this->oid,
            pack('n', $this->q->getLength()),
            $this->q->toBytes(),
        ]);
    }
}
