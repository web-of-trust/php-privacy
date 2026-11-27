<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Cryptor\Asymmetric\ElGamal;
use OpenPGP\Cryptor\Asymmetric\ElGamal\{PrivateKey, PublicKey};
use OpenPGP\Type\KeyMaterialInterface;
use phpseclib4\Crypt\Common\AsymmetricKey;
use phpseclib4\Math\BigInteger;

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
     * Constructor
     *
     * @param PrivateKey $privateKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly PrivateKey $privateKey,
        private readonly KeyMaterialInterface $publicMaterial,
    ) {
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
        $parameters = $publicMaterial->getParameters();
        $privateKey = new PrivateKey(
            Helper::readMPI($bytes),
            $parameters["y"],
            $parameters["p"],
            $parameters["g"],
        );
        return new self($privateKey, $publicMaterial);
    }

    /**
     * Generate key material by using ElGamal create key
     *
     * @param int $lSize
     * @param int $nSize
     * @return self
     */
    public static function generate(int $lSize = 2048, int $nSize = 224): self
    {
        $privateKey = ElGamal::createKey($lSize, $nSize);
        return new self(
            $privateKey,
            new ElGamalPublicKeyMaterial(
                $privateKey->getPublicKey(),
            ),
        );
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
    public function getKeyLength(): int
    {
        return $this->publicMaterial->getKeyLength();
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return [
            "x" => $this->privateKey->getX(),
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

            $prime = $this->publicMaterial->getPublicKey()->getPrime();
            $generator = $this->publicMaterial->getPublicKey()->getGenerator();
            $exponent = $this->publicMaterial->getPublicKey()->getY();

            // Check that 1 < g < p
            if (
                $generator->compare($one) <= 0 ||
                $generator->compare($prime) >= 0
            ) {
                return false;
            }

            // Expect p-1 to be large
            $pSize = $prime->getLength();
            if ($pSize < 1023) {
                return false;
            }

            // g should have order p-1
            // Check that g ** (p-1) = 1 mod p
            if (
                !$generator
                    ->modPow($prime->subtract($one), $prime)
                    ->equals($one)
            ) {
                return false;
            }

            // Re-derive public key y' = g ** x mod p
            // Expect y == y'
            // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
            $r = BigInteger::randomRange(
                $two->bitwise_leftShift($pSize - 1),
                $two->bitwise_leftShift($pSize),
            );
            $rqx = $prime->subtract($one)->multiply($r)->add($this->privateKey->getX());

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
            pack("n", $this->privateKey->getX()->getLength()),
            $this->privateKey->getX()->toBytes(),
        ]);
    }
}
