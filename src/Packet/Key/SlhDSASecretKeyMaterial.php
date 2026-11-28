<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{HashAlgorithm, SlhDsaAlgorithm};
use OpenPGP\Type\{
    KeyMaterialInterface,
    SlhDSASecretKeyMaterialInterface,
};
use PQCrypto\SLHDSA;
use PQCrypto\SLHDSA\{SigningKey, VerifyingKey};

/**
 * Post-quantum SLH-DSA secret key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SlhDSASecretKeyMaterial implements SlhDSASecretKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param string $secret
     * @param SlhDSA $slhDSA
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public function __construct(
        private readonly SigningKey $signingKey,
        private readonly KeyMaterialInterface $publicMaterial,
    ) {
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param SlhDSA $slhDSA
     * @param KeyMaterialInterface $publicMaterial
     * @return self
     */
    public static function fromBytes(
        string $bytes,
        SlhDsaAlgorithm $algo,
        KeyMaterialInterface $publicMaterial,
    ): self {
        $slh =  match ($algo) {
            SlhDsaAlgorithm::SlhDsaShake128s => new SLHDSA('shake128', 'small'),
            SlhDsaAlgorithm::SlhDsaShake128f => new SLHDSA('shake128', 'fast'),
            SlhDsaAlgorithm::SlhDsaShake256s => new SLHDSA('shake256', 'small'),
        };
        return new self(
            $slh->importSigningKey($bytes),
            $publicMaterial,
        );
    }

    /**
     * Generate key material by using SLHDSA generate key pair
     *
     * @param SlhDsaAlgorithm $slhDSA
     * @return self
     */
    public static function generate(
        SlhDsaAlgorithm $algo = SlhDsaAlgorithm::SlhDsaShake128s,
    ): self {
        $slh =  match ($algo) {
            SlhDsaAlgorithm::SlhDsaShake128s => new SLHDSA('shake128', 'small'),
            SlhDsaAlgorithm::SlhDsaShake128f => new SLHDSA('shake128', 'fast'),
            SlhDsaAlgorithm::SlhDsaShake256s => new SLHDSA('shake256', 'small'),
        };
        [$signingKey, $verifyingKey] = $slh->generateKeypair();

        return new self(
            $signingKey,
            new EdDSAPublicKeyMaterial(
                $verifyingKey,
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSigningKey(): SigningKey
    {
        return $this->signingKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getVerifyingKey(): VerifyingKey
    {
        return $this->publicMaterial->getVerifyingKey();
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
        return ["signingKey" => $this->toBytes()];
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(): bool
    {
        if ($this->publicMaterial instanceof SlhDSAPublicKeyMaterial) {
            $message = random_bytes(1024);
            $signature = $this->signingKey->sign($message);
            return $this->getVerifyingKey()->verify($signature, $message);
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->signingKey->bytes();
    }

    /**
     * {@inheritdoc}
     */
    public function sign(HashAlgorithm $hash, string $message): string
    {
        // The signature hash algo MUST have digest larger than 256 bits
        // https://www.rfc-editor.org/rfc/rfc9980.html#section-9.4
        if ($hash->digestSize() < 32) {
            throw new \RuntimeException(
                "SLH-DSA does not support {$hash->name} hash algorithm.",
            );
        }
        return $this->signingKey->sign($hash->hash($message));
    }
}
