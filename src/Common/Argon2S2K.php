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
 * Implementation of the Argon2 string-to-key specifier.
 * This S2K method hashes the passphrase using Argon2, as specified in RFC9106.
 * This provides memory hardness, further protecting the passphrase against brute-force attacks.
 * 
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Argon2S2K implements S2KInterface
{
    use S2KTrait;

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
     * String-to-key type
     */
    private readonly S2kType $type;

    /**
     * Constructor
     *
     * @param string $salt - Salt value
     * @param int $time - Number of iterations
     * @param int $parallelism - Number of parallel threads
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
        if (!function_exists('sodium_crypto_pwhash')) {
            throw new \UnexpectedValueException(
                'Argon2 string to key is unsupported',
            );
        }
        if (strlen($salt) !== self::SALT_LENGTH) {
            throw new \InvalidArgumentException(
                'Salt size must be ' . self::SALT_LENGTH . ' bytes.',
            );
        }
        if ($parallelism !== self::ARGON2_PARALLELISM) {
            throw new \InvalidArgumentException(
                'Parallelism only support ' . self::ARGON2_PARALLELISM,
            );
        }
        $this->memLimit = 2 << ($this->memoryExponent + 9);
        $this->type = S2kType::Argon2;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr($this->type->value),
            $this->salt,
            chr($this->time),
            chr($this->parallelism),
            chr($this->memoryExponent),
        ]);
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
            $this->memLimit
        );
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
}
