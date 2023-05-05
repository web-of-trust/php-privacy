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

use phpseclib3\Crypt\EC\Formats\Keys\PKCS8;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Math\BigInteger;

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
    private PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $d
     * @param ECPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private BigInteger $d,
        ECPublicParameters $publicParams
    )
    {
        $params = PKCS8::load($publicParams->getPublicKey()->toString('PKCS8'));
        $key = PKCS8::savePrivateKey(
            $d, $params['curve'], $params['QA']
        );
        $this->privateKey = EC::loadFormat('PKCS8', $key);
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
    public function encode(): string
    {
        return implode([
            pack('n', $this->d->getLength()),
            $this->d->toBytes(true),
        ]);
    }
}
