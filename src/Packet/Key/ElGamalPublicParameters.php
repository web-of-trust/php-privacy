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

use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamalPublicKey;

/**
 * ElGamal public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ElGamalPublicParameters implements KeyParametersInterface
{
    /**
     * ElGamal public key
     */
    private ElGamalPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $prime
     * @param BigInteger $order
     * @param BigInteger $exponent
     * @return self
     */
    public function __construct(
        private BigInteger $prime,
        private BigInteger $generator,
        private BigInteger $exponent
    )
    {
        $this->publicKey = new ElGamalPublicKey(
            $exponent, $prime, $generator
        );
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return ElGamalPublicParameters
     */
    public static function fromBytes(string $bytes): ElGamalPublicParameters
    {
        $prime = Helper::readMPI($bytes);

        $offset = $prime->getLengthInBytes() + 2;
        $generator = Helper::readMPI(substr($bytes, $offset));

        $offset += $generator->getLengthInBytes() + 2;
        $exponent = Helper::readMPI(substr($bytes, $offset));

        return new ElGamalPublicParameters($prime, $generator, $exponent);
    }

    /**
     * Gets public key
     *
     * @return ElGamalPublicKey
     */
    public function getPublicKey(): ElGamalPublicKey
    {
        return $this->publicKey;
    }

    /**
     * Gets prime p
     *
     * @return BigInteger
     */
    public function getPrime(): BigInteger
    {
        return $this->prime;
    }

    /**
     * Gets group generator g
     *
     * @return BigInteger
     */
    public function getGenerator(): BigInteger
    {
        return $this->generator;
    }

    /**
     * Gets exponent y (= g ** x mod p where x is secret)
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
            pack('n', $this->prime->getLength()),
            $this->prime->toBytes(),
            pack('n', $this->generator->getLength()),
            $this->generator->toBytes(),
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }
}
