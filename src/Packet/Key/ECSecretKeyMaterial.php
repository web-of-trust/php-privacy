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

use phpseclib3\Crypt\Common\{
    AsymmetricKey,
    PrivateKey,
    PublicKey,
};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves\{
    Curve25519,
    Ed25519,
};
use phpseclib3\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\{
    MontgomeryPrivate,
    PKCS8,
};
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;
use OpenPGP\Type\KeyMaterialInterface;

/**
 * EC secret key material class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class ECSecretKeyMaterial implements KeyMaterialInterface
{
    /**
     * phpseclib3 EC private key
     */
    protected readonly ECPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param KeyMaterialInterface $publicMaterial
     * @param ECPrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $d,
        private readonly KeyMaterialInterface $publicMaterial,
        ?ECPrivateKey $privateKey = null
    )
    {
        if ($privateKey instanceof ECPrivateKey) {
            $this->privateKey = $privateKey;
        }
        else {
            $format = 'PKCS8';
            $params = $publicMaterial->getParameters();
            $curve = $params['curve'];
            if ($curve instanceof Ed25519) {
                $arr = $curve->extractSecret($d->toBytes());
                $key = PKCS8::savePrivateKey(
                    $arr['dA'], $curve, $params['QA'], $arr['secret']
                );
            }
            elseif ($curve instanceof Curve25519) {
                $key = strrev($d->toBytes());
                $format = 'MontgomeryPrivate';
            }
            else {
                $key = PKCS8::savePrivateKey(
                    $d, $curve, $params['QA']
                );
            }
            $this->privateKey = EC::loadPrivateKeyFormat($format, $key);
        }
    }

    /**
     * Get private key d
     *
     * @return BigInteger
     */
    public function getD(): BigInteger
    {
        return $this->d;
    }

    /**
     * Get EC private key
     *
     * @return ECPrivateKey
     */
    public function getECPrivateKey(): ECPrivateKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKey
    {
        return $this->privateKey->getPublicKey();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicMaterial(): KeyMaterialInterface
    {
        return $this->publicMaterial;
    }

    /**
     * {@inheritdoc}
     */
    public function getAsymmetricKey(): AsymmetricKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        $params = $this->publicMaterial->getParameters();
        $curve = $params['curve'];
        if ($curve instanceof Curve25519) {
            return MontgomeryPrivate::load(
                $this->privateKey->toString('MontgomeryPrivate')
            );
        }
        else {
            return PKCS8::load($this->privateKey->toString('PKCS8'));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof ECPublicKeyMaterial) {
            $curveOid = $this->publicMaterial->getCurveOid();
            switch ($curveOid) {
                case CurveOid::Ed25519:
                case CurveOid::Curve25519:
                    $dG = Helper::bin2BigInt(
                        "\x40" . $this->privateKey->getEncodedCoordinates()
                    );
                    return $this->publicMaterial->getQ()->equals($dG);
                default:
                    $params = $this->publicMaterial->getParameters();
                    $curve = $params['curve'];
                    $QA = $curve->multiplyPoint($curve->getBasePoint(), $this->d);
                    return $QA[0]->toBigInteger()->equals($params['QA'][0]->toBigInteger()) &&
                           $QA[1]->toBigInteger()->equals($params['QA'][1]->toBigInteger());
            }
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack('n', $this->d->getLength()),
            $this->d->toBytes(),
        ]);
    }
}
