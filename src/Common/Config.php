<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{
    CompressionAlgorithm,
    HashAlgorithm,
    SymmetricAlgorithm,
};
use Psr\Log\{
    LoggerInterface,
    NullLogger,
};

/**
 * Config class
 * 
 * @package   OpenPGP
 * @category  Common
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
final class Config
{
    const VERSION = 'PHP Privacy v1.0.0';
    const COMMENT = 'PHP OpenPGP';

    private static HashAlgorithm $preferredHash = HashAlgorithm::Sha256;

    private static SymmetricAlgorithm $preferredSymmetric = SymmetricAlgorithm::Aes128;

    private static CompressionAlgorithm $preferredCompression = CompressionAlgorithm::Uncompressed;

    private static ?LoggerInterface $logger = null;

    private static int $s2kItCount = 224;

    private static bool $allowUnauthenticated = false;

    /**
     * Gets preferred hash algorithm.
     *
     * @return HashAlgorithm
     */
    public static function getPreferredHash(): HashAlgorithm
    {
        return self::$preferredHash;
    }

    /**
     * Sets preferred hash algorithm.
     *
     * @param HashAlgorithm $hash
     */
    public static function setPreferredHash(HashAlgorithm $hash): void
    {
        self::$preferredHash = $hash;
    }

    /**
     * Gets preferred symmetric algorithm.
     *
     * @return SymmetricAlgorithm
     */
    public static function getPreferredSymmetric(): SymmetricAlgorithm
    {
        return self::$preferredSymmetric;
    }

    /**
     * Sets preferred symmetric algorithm.
     *
     * @param SymmetricAlgorithm $symmetric
     */
    public static function setPreferredSymmetric(
        SymmetricAlgorithm $symmetric
    ): void
    {
        self::$preferredSymmetric = $symmetric;
    }

    /**
     * Gets preferred compression algorithm.
     *
     * @return CompressionAlgorithm
     */
    public static function getPreferredCompression(): CompressionAlgorithm
    {
        return self::$preferredCompression;
    }

    /**
     * Sets preferred compression algorithm.
     *
     * @param CompressionAlgorithm $compression
     */
    public static function setPreferredCompression(
        CompressionAlgorithm $compression
    ): void
    {
        self::$preferredCompression = $compression;
    }

    /**
     * Gets a logger.
     *
     * @return LoggerInterface
     */
    public static function getLogger(): LoggerInterface
    {
        if (!(self::$logger instanceof LoggerInterface)) {
            self::$logger = new NullLogger();
        }
        return self::$logger;
    }

    /**
     * Sets a logger.
     *
     * @param LoggerInterface $logger
     */
    public static function setLogger(LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Gets S2K iteration count byte.
     *
     * @return int
     */
    public static function getS2kItCount(): int
    {
        return self::$s2kItCount;
    }

    /**
     * Sets S2K iteration count byte.
     *
     * @param int $s2kItCount
     */
    public static function setS2kItCount(int $s2kItCount): void
    {
        self::$s2kItCount = $s2kItCount;
    }

    /**
     * Gets allow decryption of messages without integrity protection.
     *
     * @return bool
     */
    public static function allowUnauthenticated(): bool
    {
        return self::$allowUnauthenticated;
    }

    /**
     * Sets allow decryption of messages without integrity protection.
     *
     * @param bool $allow
     */
    public static function setAllowUnauthenticated(bool $allow): void
    {
        self::$allowUnauthenticated = $allow;
    }
}
