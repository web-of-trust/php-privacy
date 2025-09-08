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
use OpenPGP\Type\{KeyMaterialInterface, PublicKeyMaterialInterface};
use phpseclib3\Crypt\Common\{AsymmetricKey, PublicKey};
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PublicKey as RSAPublicKey;
use phpseclib3\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;

/**
 * RSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RSAPublicKeyMaterial implements PublicKeyMaterialInterface
{
    /**
     * phpseclib3 RSA public key
     */
    private readonly RSAPublicKey $publicKey;

    /**
     * Constructor
     *
     * @param BigInteger $modulus
     * @param BigInteger $exponent
     * @param RSAPublicKey $publicKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $modulus,
        private readonly BigInteger $exponent,
        ?RSAPublicKey $publicKey = null,
    ) {
        $this->publicKey =
            $publicKey ??
            RSA::loadPublicKey([
                "modulus" => $modulus,
                "publicExponent" => $exponent,
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
        $modulus = Helper::readMPI($bytes);
        return new self(
            $modulus,
            Helper::readMPI(substr($bytes, $modulus->getLengthInBytes() + 2)),
        );
    }

    /**
     * Get modulus n
     *
     * @return BigInteger
     */
    public function getModulus(): BigInteger
    {
        return $this->modulus;
    }

    /**
     * Get exponent e
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
        return $this->publicKey->getLength();
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
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters(): array
    {
        return PKCS8::load($this->publicKey->toString("PKCS8"));
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
            pack("n", $this->modulus->getLength()),
            $this->modulus->toBytes(),
            pack("n", $this->exponent->getLength()),
            $this->exponent->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        return $this->publicKey
            ->withHash(strtolower($hash->name))
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->verify(
                $message,
                substr(
                    $signature,
                    2,
                    Helper::bit2ByteLength(Helper::bytesToShort($signature)),
                ),
            );
    }
}
