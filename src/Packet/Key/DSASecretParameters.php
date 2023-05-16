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

use phpseclib3\Crypt\DSA\PrivateKey;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{DHKeySize, HashAlgorithm};

/**
 * DSA secret parameters class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class DSASecretParameters implements SignableParametersInterface
{
    use DSASigningTrait;

    /**
     * phpseclib3 DSA private key
     */
    private readonly PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param DSAPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly DSAPublicParameters $publicParams,
        ?PrivateKey $privateKey = null
    )
    {
        $this->privateKey = $privateKey ?? PublicKeyLoader::loadPrivateKey([
            'p' => $publicParams->getPrime(),
            'q' => $publicParams->getOrder(),
            'g' => $publicParams->getGenerator(),
            'y' => $publicParams->getExponent(),
            'x' => $exponent,
        ]);
    }

    /**
     * Reads parameters from bytes
     *
     * @param string $bytes
     * @param DSAPublicParameters $publicParams
     * @return self
     */
    public static function fromBytes(
        string $bytes, DSAPublicParameters $publicParams
    ): self
    {
        return new self(
            Helper::readMPI($bytes), $publicParams
        );
    }

    /**
     * Generates parameters by using DSA create key
     *
     * @param DHKeySize $keySize
     * @return self
     */
    public static function generate(DHKeySize $keySize): self
    {
        $privateKey = DSA::createKey($keySize->lSize(), $keySize->nSize());
        $rawKey = $privateKey->toString('Raw');
        return new self(
            $rawKey['x'],
            new DSAPublicParameters(
                $rawKey['p'],
                $rawKey['q'],
                $rawKey['g'],
                $rawKey['y'],
                $privateKey->getPublicKey(),
            ),
            $privateKey
        );
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
    public function isValid(): bool
    {
        $zero = new BigInteger(0);
        $one = new BigInteger(1);
        $two = new BigInteger(2);

        $prime = $this->publicParams->getPrime();
        $order = $this->publicParams->getOrder();
        $generator = $this->publicParams->getGenerator();
        $exponent = $this->publicParams->getExponent();

        // Check that 1 < g < p
        if ($generator->compare($one) <= 0 || $generator->compare($prime) >= 0) {
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
            $two->bitwise_leftShift($qSize - 1), $two->bitwise_leftShift($qSize)
        );
        $rqx = $order->multiply($r)->add($this->exponent);

        return $exponent->equals($generator->modPow($rqx, $prime));
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
}
