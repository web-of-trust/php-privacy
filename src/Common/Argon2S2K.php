<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\S2kType;
use OpenPGP\Type\S2KInterface;
use phpseclib3\Crypt\Random;

/**
 * Argon2 string-to-key class
 * 
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Argon2S2K implements S2KInterface
{
    /**
     * Default salt length
     */
    const SALT_LENGTH = 16;

    /**
     * Argon2 parallelism
     */
    const ARGON2_PARALLELISM = 1;

    /**
     * The maximum amount of RAM that the function will use, in bytes
     */
    private readonly int $memLimit;

    /**
     * Constructor
     *
     * @param string $salt - Salt value
     * @param int $time - Number of passes time
     * @param int $parallelism - Degree of parallelism
     * @param int $memoryExponent - The exponent of the memory size
     * @return self
     */
    public function __construct(
        private readonly string $salt,
        private readonly int $time = 4,
        private readonly int $parallelism = 1,
        private readonly int $memoryExponent = 16,
    )
    {
        if (!function_exists('sodium_crypto_pwhash') ||
            !defined('SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13')
        ) {
            throw new \UnexpectedValueException(
                'Argon2 string to key is unsupported',
            );
        }
        if ($parallelism != self::ARGON2_PARALLELISM) {
            throw new \InvalidArgumentException(
                'Degree of parallelism only support ' . self::ARGON2_PARALLELISM,
            );
        }
        $this->memLimit = 2 << ($this->memoryExponent + 9);
    }

    /**
     * Get S2K type
     *
     * @return S2kType
     */
    public function getType(): S2kType
    {
        return S2kType::Argon2;
    }

    /**
     * Get salt
     *
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * Get packet length
     *
     * @return int
     */
    public function getLength(): int
    {
        return $this->getType()->packetLength();
    }

    /**
     * {@inheritdoc}
     */
    public function produceKey(
        string $passphrase, int $keyLen
    ): string
    {
        return sodium_crypto_pwhash(
            $keyLen,
            $passphrase,
            $this->salt,
            $this->time,
            $this->memLimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    /**
     * Generate random salt string
     * 
     * @return string
     */
    public static function generateSalt(): string 
    {
        return Random::string(self::SALT_LENGTH);
    }

    /**
     * Parsing function for argon2 string-to-key specifier.
     * 
     * @param string $bytes - Payload of argon2 string-to-key specifier
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 1;
        $salt = substr($bytes, $offset, self::SALT_LENGTH);
        $offset += self::SALT_LENGTH;
        $time = ord($bytes[$offset++]);
        $parallelism = ord($bytes[$offset++]);
        $memoryExponent = ord($bytes[$offset++]);
        return new self($salt, $time, $parallelism, $memoryExponent);
    }

    /**
     * Serialize s2k information to binary string
     * 
     * @return string
     */
    public function toBytes(): string
    {
        return implode([
            chr($this->getType()->value),
            $this->salt,
            chr($this->time),
            chr($this->parallelism),
            chr($this->memoryExponent),
        ]);
    }
}
