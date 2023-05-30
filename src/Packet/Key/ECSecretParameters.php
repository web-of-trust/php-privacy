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
use phpseclib3\Crypt\EC\Curves\{
    Curve25519,
    Ed25519,
};
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Crypt\EC\Formats\Keys\{
    MontgomeryPrivate,
    PKCS8,
};
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\CurveOid;
use OpenPGP\Type\KeyParametersInterface;

/**
 * EC secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class ECSecretParameters implements KeyParametersInterface
{
    /**
     * phpseclib3 EC private key
     */
    private readonly PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param KeyParametersInterface $publicParams
     * @param PrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $d,
        private readonly KeyParametersInterface $publicParams,
        ?PrivateKey $privateKey = null
    )
    {
        if ($privateKey instanceof PrivateKey) {
            $this->privateKey = $privateKey;
        }
        else {
            $format = 'PKCS8';
            $params = $publicParams->getParameters();
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
            $this->privateKey = EC::loadFormat($format, $key);
        }
    }

    /**
     * Gets private key d
     *
     * @return BigInteger
     */
    public function getD(): BigInteger
    {
        return $this->d;
    }

    /**
     * Gets private key
     *
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicParams(): KeyParametersInterface
    {
        return $this->publicParams;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        $params = $this->publicParams->getParameters();
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
        if ($this->publicParams instanceof ECPublicParameters) {
            $curveOid = $this->publicParams->getCurveOid();
            switch ($curveOid) {
                case CurveOid::Ed25519:
                case CurveOid::Curve25519:
                    $dG = Helper::bin2BigInt(
                        "\x40" . $this->privateKey->getEncodedCoordinates()
                    );
                    return $this->publicParams->getQ()->equals($dG);
                default:
                    $params = $this->publicParams->getParameters();
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
