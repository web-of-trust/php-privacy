<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{HashAlgorithm, RSAKeySize};
use OpenPGP\Type\{KeyMaterialInterface, SecretKeyMaterialInterface};
use phpseclib3\Crypt\Common\{AsymmetricKey, PrivateKey, PublicKey};
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib3\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;

/**
 * RSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RSASecretKeyMaterial implements SecretKeyMaterialInterface
{
    /**
     * phpseclib3 RSA private key
     */
    private readonly RSAPrivateKey $privateKey;

    /**
     * Constructor
     *
     * @param BigInteger $exponent
     * @param BigInteger $primeP
     * @param BigInteger $primeQ
     * @param BigInteger $coefficient
     * @param KeyMaterialInterface $publicMaterial
     * @param RSAPrivateKey $privateKey
     * @return self
     */
    public function __construct(
        private readonly BigInteger $exponent,
        private readonly BigInteger $primeP,
        private readonly BigInteger $primeQ,
        private readonly BigInteger $coefficient,
        private readonly KeyMaterialInterface $publicMaterial,
        ?RSAPrivateKey $privateKey = null
    ) {
        $this->privateKey =
            $privateKey ??
            RSA::loadPrivateKey([
                "privateExponent" => $exponent,
                "p" => $primeP,
                "q" => $primeQ,
                "u" => $coefficient,
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
        string $bytes,
        KeyMaterialInterface $publicMaterial
    ): self {
        $exponent = Helper::readMPI($bytes);

        $offset = $exponent->getLengthInBytes() + 2;
        $primeP = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeP->getLengthInBytes() + 2;
        $primeQ = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeQ->getLengthInBytes() + 2;
        $coefficient = Helper::readMPI(substr($bytes, $offset));

        return new self(
            $exponent,
            $primeP,
            $primeQ,
            $coefficient,
            $publicMaterial
        );
    }

    /**
     * Generate key material by using RSA create key
     *
     * @param RSAKeySize $keySize
     * @return self
     */
    public static function generate(
        RSAKeySize $keySize = RSAKeySize::Normal
    ): self {
        $privateKey = RSA::createKey($keySize->value);
        $params = PKCS8::load($privateKey->toString("PKCS8"));
        $primeP = $params["primes"][1];
        $primeQ = $params["primes"][2];
        return new self(
            $params["privateExponent"],
            $primeP,
            $primeQ,
            $primeP->modInverse($primeQ),
            new RSAPublicKeyMaterial(
                $params["modulus"],
                $params["publicExponent"],
                $privateKey->getPublicKey()
            ),
            $privateKey
        );
    }

    /**
     * Get exponent d
     *
     * @return BigInteger
     */
    public function getExponent(): BigInteger
    {
        return $this->exponent;
    }

    /**
     * Get prime value p
     *
     * @return BigInteger
     */
    public function getPrimeP(): BigInteger
    {
        return $this->primeP;
    }

    /**
     * Get prime value q (p < q)
     *
     * @return BigInteger
     */
    public function getPrimeQ(): BigInteger
    {
        return $this->primeQ;
    }

    /**
     * Get multiplicative inverse of p, mod q
     *
     * @return BigInteger
     */
    public function getCoefficient(): BigInteger
    {
        return $this->coefficient;
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
        return PKCS8::load($this->privateKey->toString("PKCS8"));
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof RSAPublicKeyMaterial) {
            $one = new BigInteger(1);
            $two = new BigInteger(2);

            // expect pq = n
            if (
                !$this->primeP
                    ->multiply($this->primeQ)
                    ->equals($this->publicMaterial->getModulus())
            ) {
                return false;
            }

            // expect p*u = 1 mod q
            list(, $c) = $this->primeP
                ->multiply($this->coefficient)
                ->divide($this->primeQ);
            if (!$c->equals($one)) {
                return false;
            }

            $nSizeOver3 = (int) floor(
                $this->publicMaterial->getModulus()->getLength() / 3
            );
            $r = BigInteger::randomRange(
                $one,
                $two->bitwise_leftShift($nSizeOver3)
            );
            $rde = $r
                ->multiply($this->exponent)
                ->multiply($this->publicMaterial->getExponent());

            list(, $p) = $rde->divide($this->primeP->subtract($one));
            list(, $q) = $rde->divide($this->primeQ->subtract($one));
            return $p->equals($r) && $q->equals($r);
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            pack("n", $this->exponent->getLength()),
            $this->exponent->toBytes(),
            pack("n", $this->primeP->getLength()),
            $this->primeP->toBytes(),
            pack("n", $this->primeQ->getLength()),
            $this->primeQ->toBytes(),
            pack("n", $this->coefficient->getLength()),
            $this->coefficient->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->privateKey
            ->withHash(strtolower($hash->name))
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->sign($message);
        return implode([pack("n", strlen($signature) * 8), $signature]);
    }
}
