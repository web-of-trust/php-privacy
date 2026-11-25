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
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        private readonly ?AeadAlgorithm $aead = null,
    ) {}

    /**
     * Read session key from binary string
     *
     * Expects the layout of a v3 PKESK session key:
     * one octet symmetric algorithm, the key, two octets checksum.
     * This is the inverse of toBytesWithChecksum(), not of toBytes().
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        if (strlen($bytes) < 3) {
            throw new \LengthException("Session key data is too short.");
        }
        $symmetric = SymmetricAlgorithm::from($bytes[0]);
        $key = substr($bytes, 1, strlen($bytes) - 3);
        if (strlen($key) !== $symmetric->keySizeInByte()) {
            throw new \LengthException(
                "Session key length does not match {$symmetric->name}.",
            );
        }
        $sessionKey = new self($key, $symmetric);
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
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        ?AeadAlgorithm $aead = null,
    ): self {
        return new self(
            random_bytes($symmetric->keySizeInByte()),
            $symmetric,
            $aead,
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
     *
     * Symmetric algorithm octet and key, without checksum,
     * as encrypted in a v4 SKESK packet (RFC 9580, section 5.3).
     * Use toBytesWithChecksum() for the input of fromBytes().
     */
    public function toBytes(): string
    {
        return implode([$this->symmetric->value, $this->encryptionKey]);
    }

    /**
     * Symmetric algorithm octet, key and two octets checksum,
     * as encrypted in a v3 PKESK packet (RFC 9580, section 5.1).
     * This is the inverse of fromBytes().
     *
     * @return string
     */
    public function toBytesWithChecksum(): string
    {
        return implode([$this->toBytes(), $this->computeChecksum()]);
    }
}
