<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use phpseclib3\Crypt\Random;
use OpenPGP\Enum\SymmetricAlgorithm as Algorithm;
use OpenPGP\Type\SessionKeyInterface;

/**
 * Session key class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SessionKey implements SessionKeyInterface
{
    /**
     * Constructor
     *
     * @param string $encryptionKey
     * @param Algorithm $symmetric
     * @return self
     */
    public function __construct(
        private readonly string $encryptionKey,
        private readonly Algorithm $symmetric = Algorithm::Aes128
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
            SymmetricAlgorithm::from(ord($bytes[0]))
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
     * @param Algorithm $symmetric
     * @return self
     */
    public static function produceKey(
        Algorithm $symmetric = Algorithm::Aes128
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
    public function getSymmetric(): Algorithm
    {
        return $this->symmetric;
    }

    /**
     * {@inheritdoc}
     */
    public function computeChecksum(): string
    {
        $sum = 0;
        $keyLen = strlen($this->encryptionKey);
        for ($i = 0; $i < $keyLen; $i++) {
          $sum = ($sum + ord($this->encryptionKey[$i])) & 0xffff;
        }
        return pack('n', $sum);
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
