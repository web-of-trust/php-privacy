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
enum HashAlgorithm: int
{
    case Unknown = 0;

    case Md5 = 1;

    case Sha1 = 2;

    case Ripemd160 = 3;

    case Sha256 = 8;

    case Sha384 = 9;

    case Sha512 = 10;

    case Sha224 = 11;

    case Sha3_256 = 12;

    case Sha3_512 = 14;

    /**
     * Digest Size
     *
     * @return int
     */
    public function digestSize(): int
    {
        return match($this) {
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
     * V6 Signature Salt Size
     *
     * @return int
     */
    public function saltSize(): int
    {
        return match($this) {
            self::Unknown, self::Md5, self::Sha1, self::Ripemd160 => 0,
            self::Sha224, self::Sha256, self::Sha3_256 => 16,
            self::Sha384 => 24,
            self::Sha512, self::Sha3_512 => 32,
        };
    }

    /**
     * Identifiers for RSA Signatures
     * Use of EMSA‑PKCS1‑v1_5 Padding Registry
     *
     * @return string
     */
    public function oid(): string
    {
        return match($this) {
            self::Unknown => '',
            self::Md5 => '1.2.840.113549.2.5',
            self::Sha1 => '1.3.14.3.2.26',
            self::Ripemd160 => '1.3.36.3.2.1',
            self::Sha256 => '2.16.840.1.101.3.4.2.1',
            self::Sha384 => '2.16.840.1.101.3.4.2.2',
            self::Sha512 => '2.16.840.1.101.3.4.2.3',
            self::Sha224 => '2.16.840.1.101.3.4.2.4',
            self::Sha3_256 => '2.16.840.1.101.3.4.2.8',
            self::Sha3_512 => '2.16.840.1.101.3.4.2.10',
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
            strtolower(str_replace('_', '-', $this->name)), $message, $binary
        );
    }
}
