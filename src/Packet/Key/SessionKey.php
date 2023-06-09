<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\Random;
use OpenPGP\Enum\SymmetricAlgorithm as Symmetric;
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
     * @param Symmetric $symmetric
     * @return self
     */
    public function __construct(
        private readonly string $encryptionKey,
        private readonly Symmetric $symmetric = Symmetric::Aes128
    )
    {
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
            Symmetric::from(ord($bytes[0]))
        );

        $checksum = substr($bytes, strlen($bytes) - 2);
        $computedChecksum = $sessionKey->computeChecksum();
        if ($computedChecksum !== $checksum) {
            throw new \UnexpectedValueException(
                'Session key decryption error'
            );
        }

        return $sessionKey;
    }

    /**
     * Produce session key specify by symmetric algorithm
     *
     * @param Symmetric $symmetric
     * @return self
     */
    public static function produceKey(
        Symmetric $symmetric = Symmetric::Aes128
    ): self
    {
        return new self(
            Random::string($symmetric->keySizeInByte()),
            $symmetric
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
    public function getSymmetric(): Symmetric
    {
        return $this->symmetric;
    }

    /**
     * {@inheritdoc}
     */
    public function computeChecksum(): string
    {
        $sum = array_sum(array_map(
            static fn ($char) => ord($char),
            str_split($this->encryptionKey)
        ));
        return pack('n', $sum & 0xffff);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr($this->symmetric->value),
            $this->encryptionKey,
        ]);
    }
}
