<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;
use OpenPGP\Type\{ECKeyMaterialInterface, KeyMaterialInterface};
use phpseclib3\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\Curves\{Curve25519, Ed25519};
use phpseclib3\Crypt\EC\PrivateKey as ECPrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\{MontgomeryPrivate, PKCS8};
use phpseclib3\Math\BigInteger;

/**
 * EC secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class ECSecretKeyMaterial implements
    ECKeyMaterialInterface,
    KeyMaterialInterface
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
    ) {
        if ($privateKey instanceof ECPrivateKey) {
            $this->privateKey = $privateKey;
        } else {
            $format = "PKCS8";
            $params = $publicMaterial->getParameters();
            $curve = $params["curve"];
            if ($curve instanceof Curve25519) {
                $key = strrev($d->toBytes());
                $format = "MontgomeryPrivate";
            } elseif ($curve instanceof Ed25519) {
                $arr = $curve->extractSecret($d->toBytes());
                $key = PKCS8::savePrivateKey(
                    $arr["dA"],
                    $curve,
                    $params["QA"],
                    $arr["secret"]
                );
            } else {
                $key = PKCS8::savePrivateKey($d, $curve, $params["QA"]);
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
     * {@inheritdoc}
     */
    public function getECKey(): EC
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
    public function getKeyLength(): int
    {
        return $this->publicMaterial->getKeyLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        $params = $this->publicMaterial->getParameters();
        $curve = $params["curve"];
        if ($curve instanceof Curve25519) {
            return MontgomeryPrivate::load(
                $this->privateKey->toString("MontgomeryPrivate")
            );
        } else {
            return PKCS8::load($this->privateKey->toString("PKCS8"));
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
                    return $this->publicMaterial
                        ->getQ()
                        ->equals(
                            Helper::bin2BigInt(
                                "\x40" .
                                $this->privateKey->getEncodedCoordinates()
                            )
                        );
                default:
                    $params = $this->publicMaterial->getParameters();
                    $QA = $params["QA"];
                    $curve = $params["curve"];
                    list($x, $y) = $curve->multiplyPoint(
                        $curve->getBasePoint(),
                        $this->d
                    );
                    return $x->equals($QA[0]) && $y->equals($QA[1]);
            }
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([pack("n", $this->d->getLength()), $this->d->toBytes()]);
    }
}
