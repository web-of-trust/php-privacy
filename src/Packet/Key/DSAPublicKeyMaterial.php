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
    PublicKey,
};
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\DSA\PublicKey as DSAPublicKey;
use phpseclib3\Crypt\DSA\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Type\{
    KeyMaterialInterface,
    PublicKeyMaterialInterface,
};

/**
 * DSA public key material class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class DSAPublicKeyMaterial implements PublicKeyMaterialInterface
{
    /**
     * phpseclib3 DSA public key
     */
    private readonly DSAPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $prime
     * @param BigInteger $order
     * @param BigInteger $generator
     * @param BigInteger $exponent
     * @param DSAPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $prime,
        private readonly BigInteger $order,
        private readonly BigInteger $generator,
        private readonly BigInteger $exponent,
        ?DSAPublicKey $publicKey = null
    )
    {
        $this->publicKey = $publicKey ?? DSA::load([
            'y' => $exponent,
            'p' => $prime,
            'q' => $order,
            'g' => $generator,
        ]);
    }

    /**
     * Reads key material from bytes
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
        return PKCS8::load($this->publicKey->toString('PKCS8'));
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

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature
    ): bool
    {
        $r = Helper::readMPI($signature);
        $s = Helper::readMPI(substr($signature, $r->getLengthInBytes() + 2));
        return $this->publicKey
            ->withSignatureFormat('Raw')
            ->withHash(strtolower($hash->name))
            ->verify($message, ['r' => $r, 's' => $s]);
    }
}
