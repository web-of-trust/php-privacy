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

use phpseclib3\Crypt\DSA\PublicKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

use OpenPGP\Common\Helper;

/**
 * DSA public parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class DSAPublicParameters implements VerifiableParametersInterface
{
    use DSAVerifyingTrait;

    /**
     * phpseclib3 DSA public key
     */
    private readonly PublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $prime
     * @param BigInteger $order
     * @param BigInteger $generator
     * @param BigInteger $exponent
     * @param PublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $prime,
        private readonly BigInteger $order,
        private readonly BigInteger $generator,
        private readonly BigInteger $exponent,
        ?PublicKey $publicKey = null
    )
    {
        $this->publicKey = $publicKey ?? PublicKeyLoader::loadPublicKey([
            'p' => $prime,
            'q' => $order,
            'g' => $generator,
            'y' => $exponent,
        ]);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $prime = Helper::readMPI($bytes);

        $offset = $prime->getLengthInBytes() + 2;
        $order = Helper::readMPI(substr($bytes, $offset));

        $offset += $order->getLengthInBytes() + 2;
        $generator = Helper::readMPI(substr($bytes, $offset));

        $offset += $generator->getLengthInBytes() + 2;
        $exponent = Helper::readMPI(substr($bytes, $offset));

        return new self(
            $prime,
            $order,
            $generator,
            $exponent
        );
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
     * Gets group order q (q is a prime divisor of p-1)
     *
     * @return BigInteger
     */
    public function getOrder(): BigInteger
    {
        return $this->order;
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
    public function toBytes(): string
    {
        return implode([
            pack('n', $this->prime->getLength()),
            $this->prime->toBytes(),
            pack('n', $this->order->getLength()),
            $this->order->toBytes(),
            pack('n', $this->generator->getLength()),
            $this->generator->toBytes(),
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }
}
