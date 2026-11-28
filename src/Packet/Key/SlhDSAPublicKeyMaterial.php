<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{HashAlgorithm, SlhDsaAlgorithm};
use OpenPGP\Type\{KeyMaterialInterface, SlhDSAPublicKeyMaterialInterface};
use PQCrypto\SLHDSA;
use PQCrypto\SLHDSA\VerifyingKey;

/**
 * Post-quantum SLH-DSA public key material class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SlhDSAPublicKeyMaterial implements SlhDSAPublicKeyMaterialInterface
{
    /**
     * Constructor
     *
     * @param VerifyingKey $verifyingKey
     * @return self
     */
    public function __construct(
        private readonly VerifyingKey $verifyingKey,
    ) {
    }

    /**
     * Read key material from bytes
     *
     * @param string $bytes
     * @param SlhDsaAlgorithm $algo
     * @return self
     */
    public static function fromBytes(string $bytes, SlhDsaAlgorithm $algo): self
    {
        $slh =  match ($algo) {
            SlhDsaAlgorithm::SlhDsaShake128s => new SLHDSA('shake128', 'small'),
            SlhDsaAlgorithm::SlhDsaShake128f => new SLHDSA('shake128', 'fast'),
            SlhDsaAlgorithm::SlhDsaShake256s => new SLHDSA('shake256', 'small'),
        };
        return new self($slh->importVerifyingKey($bytes));
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return strlen($this->verifyingKey->bytes()) * 8;
    }

    /**
     * {@inheritdoc}
     */
    public function getVerifyingKey(): VerifyingKey
    {
        return $this->verifyingKey;
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
    public function getParameters(): array
    {
        return ["verifyingKey" => $this->toBytes()];
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
        return $this->verifyingKey->bytes();
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        HashAlgorithm $hash,
        string $message,
        string $signature,
    ): bool {
        // The signature hash algo MUST have digest larger than 256 bits
        // https://www.rfc-editor.org/rfc/rfc9980.html#section-9.4
        if ($hash->digestSize() < 32) {
            throw new \RuntimeException(
                "SLH-DSA does not support {$hash->name} hash algorithm.",
            );
        }
        return $this->verifyingKey->verify($signature, $hash->hash($message));
    }
}
