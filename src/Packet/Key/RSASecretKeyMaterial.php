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
use phpseclib4\Crypt\Common\{PrivateKey, PublicKey};
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PrivateKey as RSAPrivateKey;
use phpseclib4\Math\BigInteger;

/**
 * RSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class RSASecretKeyMaterial implements SecretKeyMaterialInterface
{
    private readonly array $parameters;

    /**
     * Constructor
     *
     * @param RSAPrivateKey $privateKey
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly RSAPrivateKey $privateKey,
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
        $exponent = Helper::readMPI($bytes);

        $offset = $exponent->getLengthInBytes() + 2;
        $primeP = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeP->getLengthInBytes() + 2;
        $primeQ = Helper::readMPI(substr($bytes, $offset));

        $offset += $primeQ->getLengthInBytes() + 2;
        $coefficient = Helper::readMPI(substr($bytes, $offset));

        $privateKey = RSA::loadPrivateKey([
            "privateExponent" => $exponent,
            "p" => $primeP,
            "q" => $primeQ,
            "u" => $coefficient,
            ...$publicMaterial->getParameters(),
        ]);

        return new self($privateKey, $publicMaterial);
    }

    /**
     * Generate key material by using RSA create key
     *
     * @param RSAKeySize $keySize
     * @return self
     */
    public static function generate(
        RSAKeySize $keySize = RSAKeySize::Normal,
    ): self {
        $privateKey = RSA::createKey($keySize->value);
        return new self(
            $privateKey,
            new RSAPublicKeyMaterial(
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
        if ($this->publicMaterial instanceof RSAPublicKeyMaterial) {
            $one = new BigInteger(1);
            $two = new BigInteger(2);

            $exponent = $this->parameters["d"];
            $primeP = $this->parameters["primes"][1];
            $primeQ = $this->parameters["primes"][2];
            $coefficient = $primeP->modInverse($primeQ);

            $params = $this->publicMaterial->getParameters();
            $modulus = $params["n"];
            $publicExponent = $params["e"];

            // expect pq = n
            if (!$primeP->multiply($primeQ)->equals($modulus)) {
                return false;
            }

            // expect p*u = 1 mod q
            [, $c] = $primeP->multiply($coefficient)->divide($primeQ);
            if (!$c->equals($one)) {
                return false;
            }

            $nSizeOver3 = (int) floor(
                $modulus->getLength() / 3,
            );
            $r = BigInteger::randomRange(
                $one,
                $two->bitwise_leftShift($nSizeOver3),
            );
            $rde = $r
                ->multiply($exponent)
                ->multiply($publicExponent);

            [, $p] = $rde->divide($primeP->subtract($one));
            [, $q] = $rde->divide($primeQ->subtract($one));
            return $p->equals($r) && $q->equals($r);
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $exponent = $this->parameters["d"];
        $primeP = $this->parameters["primes"][1];
        $primeQ = $this->parameters["primes"][2];
        $coefficient = $primeP->modInverse($primeQ);
        return implode([
            pack("n", $exponent->getLength()),
            $exponent->toBytes(),
            pack("n", $primeP->getLength()),
            $primeP->toBytes(),
            pack("n", $primeQ->getLength()),
            $primeQ->toBytes(),
            pack("n", $coefficient->getLength()),
            $coefficient->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        $signature = $this->privateKey
            ->withHash(strtolower(str_replace("_", "-", $hash->name)))
            ->withPadding(RSA::SIGNATURE_PKCS1)
            ->sign($message);
        // The signature is written as an MPI (RFC 9580, section 5.2.3.1),
        // which carries no leading zero octets (section 3.2).
        $value = Helper::bin2BigInt($signature);
        return implode([pack("n", $value->getLength()), $value->toBytes()]);
    }
}
