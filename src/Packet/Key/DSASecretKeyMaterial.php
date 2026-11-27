<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Type\{KeyMaterialInterface, SecretKeyMaterialInterface};
use phpseclib4\Crypt\Common\{PrivateKey, PublicKey};
use phpseclib4\Crypt\DSA;
use phpseclib4\Crypt\DSA\PrivateKey as DSAPrivateKey;
use phpseclib4\Math\BigInteger;

/**
 * DSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class DSASecretKeyMaterial implements SecretKeyMaterialInterface
{
    private readonly array $parameters;

    /**
     * Constructor
     *
     * @param DSAPrivateKey $privateKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly DSAPrivateKey $privateKey,
        private readonly KeyMaterialInterface $publicMaterial,
    ) {
        $this->parameters = $privateKey->toArray();
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        KeyMaterialInterface $publicMaterial,
    ): self {
        $privateKey = DSA::loadPrivateKey([
            "x" => Helper::readMPI($bytes),
            ...$publicMaterial->getParameters(),
        ]);
        return new self($privateKey, $publicMaterial);
    }

    /**
     * Generate key material by using DSA create key
     *
     * @param int $lSize
     * @param int $nSize
     * @return self
     */
    public static function generate(int $lSize = 2048, int $nSize = 224): self
    {
        $privateKey = DSA::createKey($lSize, $nSize);
        return new self(
            $params["x"],
            new DSAPublicKeyMaterial(
                $privateKey->getPublicKey(),
            ),
        );
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
    public function getKeyLength(): int
    {
        return $this->publicMaterial->getKeyLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return $this->parameters;
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

            $params = $this->publicMaterial->getParameters();
            $prime = $params["p"];
            $order = $params["q"];
            $generator = $params["g"];
            $exponent = $params["y"];

            // Check that 1 < g < p
            if (
                $generator->compare($one) <= 0 ||
                $generator->compare($prime) >= 0
            ) {
                return false;
            }

            // Check that subgroup order q divides p-1
            [, $c] = $prime->subtract($one)->divide($order);
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
                $two->bitwise_leftShift($qSize),
            );
            $rqx = $order->multiply($r)->add($this->parameters["x"]);

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
            pack("n", $this->parameters["x"]->getLength()),
            $this->parameters["x"]->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->privateKey
            ->withSignatureFormat("Raw")
            ->withHash(strtolower(str_replace("_", "-", $hash->name)))
            ->sign($message);
        return implode([
            pack("n", $signature["r"]->getLength()),
            $signature["r"]->toBytes(),
            pack("n", $signature["s"]->getLength()),
            $signature["s"]->toBytes(),
        ]);
    }
}
