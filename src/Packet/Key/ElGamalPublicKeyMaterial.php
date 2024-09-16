<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal\PublicKey;
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Math\BigInteger;

/**
 * ElGamal public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ElGamalPublicKeyMaterial implements KeyMaterialInterface
{
    /**
     * ElGamal public key
     */
    private readonly PublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $prime
     * @param BigInteger $generator
     * @param BigInteger $exponent
     * @param PublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $prime,
        private readonly BigInteger $generator,
        private readonly BigInteger $exponent,
        ?PublicKey $publicKey = null
    )
    {
        $this->publicKey = $publicKey ?? new PublicKey(
            $exponent, $prime, $generator
        );
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $prime = Helper::readMPI($bytes);

        $offset = $prime->getLengthInBytes() + 2;
        $generator = Helper::readMPI(substr($bytes, $offset));

        $offset += $generator->getLengthInBytes() + 2;
        $exponent = Helper::readMPI(substr($bytes, $offset));

        return new self(
            $prime,
            $generator,
            $exponent
        );
    }

    /**
     * Get prime p
     *
     * @return BigInteger
     */
    public function getPrime(): BigInteger
    {
        return $this->prime;
    }

    /**
     * Get group generator g
     *
     * @return BigInteger
     */
    public function getGenerator(): BigInteger
    {
        return $this->generator;
    }

    /**
     * Get exponent y (= g ** x mod p where x is secret)
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
    public function getKeyLength(): int
    {
        return $this->prime->getLength();
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
    public function getAsymmetricKey(): AsymmetricKey
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
    public function getParameters(): array
    {
        return [
            'p' => $this->prime,
            'g' => $this->generator,
            'y' => $this->exponent,
        ];
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
            pack('n', $this->generator->getLength()),
            $this->generator->toBytes(),
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }
}
