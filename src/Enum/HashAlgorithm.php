<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Hash algorithm enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum HashAlgorithm: string
{
    case Unknown = "\x00";

    case Md5 = "\x01";

    case Sha1 = "\x02";

    case Ripemd160 = "\x03";

    case Sha256 = "\x08";

    case Sha384 = "\x09";

    case Sha512 = "\x0A";

    case Sha224 = "\x0B";

    case Sha3_256 = "\x0C";

    case Sha3_512 = "\x0E";

    /**
     * Digest size
     *
     * @return int
     */
    public function digestSize(): int
    {
        return match ($this) {
            self::Unknown => 0,
            self::Md5 => 16,
            self::Sha1, self::Ripemd160 => 20,
            self::Sha256, self::Sha3_256 => 32,
            self::Sha384 => 48,
            self::Sha512, self::Sha3_512 => 64,
            self::Sha224 => 28,
        };
    }

    /**
     * Signature salt size
     *
     * @return int
     */
    public function saltSize(): int
    {
        return match ($this) {
            self::Unknown, self::Md5, self::Sha1, self::Ripemd160 => 0,
            self::Sha224, self::Sha256, self::Sha3_256 => 16,
            self::Sha384 => 24,
            self::Sha512, self::Sha3_512 => 32,
        };
    }

    /**
     * Generate a hash value (message digest)
     *
     * @param string $message
     * @param bool $binary
     * @return string
     */
    public function hash(string $message, bool $binary = true): string
    {
        return hash(
            strtolower(str_replace("_", "-", $this->name)),
            $message,
            $binary,
        );
    }
}
