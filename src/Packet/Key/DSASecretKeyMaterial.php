<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    DHKeySize,
    HashAlgorithm,
};
use OpenPGP\Type\{
    KeyMaterialInterface,
    SecretKeyMaterialInterface,
};
use phpseclib3\Crypt\Common\{
    AsymmetricKey,
    PrivateKey,
    PublicKey,
};
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\DSA\PrivateKey as DSAPrivateKey;
use phpseclib3\Crypt\DSA\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;

/**
 * DSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class DSASecretKeyMaterial implements SecretKeyMaterialInterface
{
    /**
     * phpseclib3 DSA private key
     */
    private readonly DSAPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param KeyMaterialInterface $publicMaterial
     * @param DSAPrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly KeyMaterialInterface $publicMaterial,
        ?DSAPrivateKey $privateKey = null,
    )
    {
        $this->privateKey = $privateKey ?? DSA::loadPrivateKey([
            'x' => $exponent,
            ...$publicMaterial->getParameters(),
        ]);
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes, KeyMaterialInterface $publicMaterial
    ): self
    {
        return new self(
            Helper::readMPI($bytes), $publicMaterial
        );
    }

    /**
     * Generate key material by using DSA create key
     *
     * @param DHKeySize $keySize
     * @return self
     */
    public static function generate(
        DHKeySize $keySize = DHKeySize::Medium
    ): self
    {
        $privateKey = DSA::createKey(
            $keySize->lSize(), $keySize->nSize()
        );
        $params = PKCS8::load($privateKey->toString('PKCS8'));
        return new self(
            $params['x'],
            new DSAPublicKeyMaterial(
                $params['p'],
                $params['q'],
                $params['g'],
                $params['g']->powMod($params['x'], $params['p']),
                $privateKey->getPublicKey(),
            ),
            $privateKey,
        );
    }

    /**
     * Get exponent x
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
        return PKCS8::load($this->privateKey->toString('PKCS8'));
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof DSAPublicKeyMaterial) {
            $zero = new BigInteger(0);
            $one = new BigInteger(1);
            $two = new BigInteger(2);

            $prime = $this->publicMaterial->getPrime();
            $order = $this->publicMaterial->getOrder();
            $generator = $this->publicMaterial->getGenerator();
            $exponent = $this->publicMaterial->getExponent();

            // Check that 1 < g < p
            if ($generator->compare($one) <= 0 ||
                $generator->compare($prime) >= 0) {
                return false;
            }

            // Check that subgroup order q divides p-1
            list(, $c) = $prime->subtract($one)->divide($order);
            if (!$c->equals($zero)) {
                return false;
            }

            // g has order q
            // Check that g ** q = 1 mod p
            if (!$generator->modPow($order, $prime)->equals($one)) {
                return false;
            }

            // Check q is large and probably prime (we mainly want to avoid small factors)
            $qSize = $order->getLength();
            if ($qSize < 150 || !$order->isPrime()) {
                return false;
            }

            // Re-derive public key y' = g ** x mod p
            // Expect y == y'
            // Blinded exponentiation computes g**{rq + x} to compare to y
            $r = BigInteger::randomRange(
                $two->bitwise_leftShift($qSize - 1),
                $two->bitwise_leftShift($qSize)
            );
            $rqx = $order->multiply($r)->add($this->exponent);

            return $exponent->equals($generator->modPow($rqx, $prime));
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack('n', $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->privateKey
            ->withSignatureFormat('Raw')
            ->withHash(strtolower($hash->name))
            ->sign($message);
        return implode([
            pack('n', $signature['r']->getLength()),
            $signature['r']->toBytes(),
            pack('n', $signature['s']->getLength()),
            $signature['s']->toBytes(),
        ]);
    }
}
