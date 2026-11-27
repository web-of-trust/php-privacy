<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\{HashAlgorithm, SlhDSA};
use OpenPGP\Type\SlhDSAPublicKeyMaterialInterface;
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
     * @param string $public
     * @param SlhDSA $slhDSA
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
     * @param SlhDSA $slhDSA
     * @return self
     */
    public static function fromBytes(string $bytes, SlhDSA $slhDSA): self
    {
        $slh =  match ($slhDSA) {
            SlhDSA::SlhDsaShake128s => new SLHDSA('shake128', 'small'),
            SlhDSA::SlhDsaShake128f => new SLHDSA('shake128', 'fast'),
            SlhDSA::SlhDsaShake256s => new LHDSA('shake256', 'small'),
        };
        return new self($slh->importVerifyingKey($bytes));
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return $this->slhDSA->publicSize() * 8;
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
        if ($hash->digestSize() < 32) {
            throw new \RuntimeException(
                "SLH-DSA does not support {$hash->name} hash algorithm.",
            );
        }
        return $this->verifyingKey->verify($signature, $hash->hash($message));
    }
}
