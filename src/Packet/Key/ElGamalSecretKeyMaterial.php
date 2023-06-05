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

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Math\BigInteger;
use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal;
use OpenPGP\Cryptor\Asymmetric\ElGamal\{
    PrivateKey,
    PublicKey,
};
use OpenPGP\Enum\DHKeySize;
use OpenPGP\Type\KeyMaterialInterface;

/**
 * ElGamal secret key material class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ElGamalSecretKeyMaterial implements KeyMaterialInterface
{
    /**
     * ElGamal private key
     */
    private readonly PrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly KeyMaterialInterface $publicMaterial,
        ?PrivateKey $privateKey = null
    )
    {
        $parameters = $publicMaterial->getParameters();
        $this->privateKey = $privateKey ?? new PrivateKey(
            $exponent,
            $parameters['y'],
            $parameters['p'],
            $parameters['g']
        );
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
     * Generate key material by using ElGamal create key
     *
     * @param DHKeySize $keySize
     * @return self
     */
    public static function generate(
        DHKeySize $keySize = DHKeySize::L2048_N224
    ): self
    {
        $privateKey = ElGamal::createKey(
            $keySize->lSize(), $keySize->nSize()
        );
        return new self(
            $privateKey->getX(),
            new ElGamalPublicKeyMaterial(
                $privateKey->getPrime(),
                $privateKey->getGenerator(),
                $privateKey->getY(),
                $privateKey->getPublicKey(),
            ),
            $privateKey
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
     * Get private key
     *
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * Get public key
     *
     * @return PublicKey
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
    public function getParameters(): array
    {
        return [
            'x' => $this->exponent,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof ElGamalPublicKeyMaterial) {
            $one = new BigInteger(1);
            $two = new BigInteger(2);

            $prime = $this->publicMaterial->getPrime();
            $generator = $this->publicMaterial->getGenerator();
            $exponent = $this->publicMaterial->getExponent();

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
            if (!$generator->modPow(
                $prime->subtract($one), $prime
            )->equals($one)) {
                return false;
            }

            // Re-derive public key y' = g ** x mod p
            // Expect y == y'
            // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
            $r = BigInteger::randomRange(
                $two->bitwise_leftShift($pSize - 1),
                $two->bitwise_leftShift($pSize)
            );
            $rqx = $prime->subtract($one)
                ->multiply($r)
                ->add($this->exponent);

            return $exponent->equals(
                $generator->modPow($rqx, $prime)
            );
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
}
