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
use OpenPGP\Cryptor\Asymmetric\{ElGamal, ElGamalPrivateKey};
use OpenPGP\Enum\DHKeySize;

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
    private readonly ElGamalPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param ElGamalPublicParameters $publicParams
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly ElGamalPublicParameters $publicParams,
        ?ElGamalPrivateKey $privateKey = null
    )
    {
        $this->privateKey = $privateKey ?? new ElGamalPrivateKey(
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
     * @return self
     */
    public static function fromBytes(
        string $bytes, ElGamalPublicParameters $publicParams
    ): self
    {
        return new self(
            Helper::readMPI($bytes), $publicParams
        );
    }

    /**
     * Generates parameters by using ElGamal create key
     *
     * @param DHKeySize $keySize
     * @return self
     */
    public static function generate(DHKeySize $keySize): self
    {
        $privateKey = ElGamal::createKey($keySize->lSize(), $keySize->nSize());
        return new self(
            $privateKey->getX(),
            new ElGamalPublicParameters(
                $privateKey->getPrime(),
                $privateKey->getGenerator(),
                $privateKey->getY(),
                $privateKey->getPublicKey(),
            ),
            $privateKey
        );
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
    public function getPublicParams(): KeyParametersInterface
    {
        return $this->publicParams;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        $one = new BigInteger(1);
        $two = new BigInteger(2);

        $prime = $this->publicParams->getPrime();
        $generator = $this->publicParams->getGenerator();
        $exponent = $this->publicParams->getExponent();

        // Check that 1 < g < p
        if ($generator->compare($one) <= 0 || $generator->compare($prime) >= 0) {
            return false;
        }

        // Expect p-1 to be large
        $pSize = $prime->getLength();
        if ($pSize < 1023) {
            return false;
        }

        // g should have order p-1
        // Check that g ** (p-1) = 1 mod p
        if (!$generator->modPow($prime->subtract($one), $prime)->equals($one)) {
            return false;
        }

        // Re-derive public key y' = g ** x mod p
        // Expect y == y'
        // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
        $r = BigInteger::randomRange(
            $two->bitwise_leftShift($pSize - 1), $two->bitwise_leftShift($pSize)
        );
        $rqx = $prime->subtract($one)->multiply($r)->add($this->exponent);

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
