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

use phpseclib3\Math\BigInteger;

use OpenPGP\Cryptor\Asymmetric\ElGamalPrivateKey;
use OpenPGP\Common\Helper;

/**
 * ElGamal secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalSecretParameters implements KeyParametersInterface
{
    /**
     * ElGamal private key
     */
    private ElGamalPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param ElGamalPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private BigInteger $exponent, ElGamalPublicParameters $publicParams
    )
    {
        $this->privateKey = ElGamalPrivateKey(
            $exponent,
            $publicParams->getExponent(),
            $publicParams->getPrime(),
            $publicParams->getGenerator()
        );
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param ElGamalPublicParameters $publicParams
     * @return ElGamalSecretParameters
     */
    public static function fromBytes(
        string $bytes, ElGamalPublicParameters $publicParams
    ): ElGamalSecretParameters
    {
        return ElGamalSecretParameters(Helper::readMPI($bytes), $publicParams);
    }

    /**
     * Gets private key
     *
     * @return ElGamalPrivateKey
     */
    public function getPrivateKey(): ElGamalPrivateKey
    {
        return $this->privateKey;
    }

    /**
     * Gets exponent x
     *
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        return $this->exponent;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        return implode([
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }
}
