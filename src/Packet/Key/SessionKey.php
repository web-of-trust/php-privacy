<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{AeadAlgorithm, SymmetricAlgorithm};
use OpenPGP\Type\SessionKeyInterface;
use phpseclib3\Crypt\Random;

/**
 * Session key class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SessionKey implements SessionKeyInterface
{
    /**
     * Constructor
     *
     * @param string $encryptionKey
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @return self
     */
    public function __construct(
        private readonly string $encryptionKey,
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private readonly ?AeadAlgorithm $aead = null
    ) {
    }

    /**
     * Read session key from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $sessionKey = new self(
            substr($bytes, 1, strlen($bytes) - 3),
            SymmetricAlgorithm::from(ord($bytes[0]))
        );
        return $sessionKey->checksum(substr($bytes, strlen($bytes) - 2));
    }

    /**
     * Produce session key specify by symmetric algorithm
     *
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @return self
     */
    public static function produceKey(
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?AeadAlgorithm $aead = null
    ): self {
        return new self(
            Random::string($symmetric->keySizeInByte()),
            $symmetric,
            $aead
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptionKey(): string
    {
        return $this->encryptionKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getSymmetric(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * {@inheritdoc}
     */
    public function getAead(): ?AeadAlgorithm
    {
        return $this->aead;
    }

    /**
     * {@inheritdoc}
     */
    public function checksum(string $checksum): self
    {
        if (strcmp($this->computeChecksum(), $checksum) !== 0) {
            throw new \RuntimeException("Session key checksum mismatch!");
        }
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function computeChecksum(): string
    {
        return Helper::computeChecksum($this->encryptionKey);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([chr($this->symmetric->value), $this->encryptionKey]);
    }
}
