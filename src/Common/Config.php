<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{
    AeadAlgorithm,
    CompressionAlgorithm,
    HashAlgorithm,
    SymmetricAlgorithm
};
use Psr\Log\{LoggerInterface, NullLogger};

/**
 * Config class
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class Config
{
    const VERSION = "PHP Privacy v1";
    const COMMENT = "The PHP OpenPGP library";

    private static HashAlgorithm $preferredHash = HashAlgorithm::Sha256;

    private static SymmetricAlgorithm $preferredSymmetric = SymmetricAlgorithm::Aes128;

    private static CompressionAlgorithm $preferredCompression = CompressionAlgorithm::Uncompressed;

    private static ?LoggerInterface $logger = null;

    private static HashAlgorithm $s2kHash = HashAlgorithm::Sha256;

    private static AeadAlgorithm $preferredAead = AeadAlgorithm::Eax;

    private static int $s2kItCount = 224;

    private static int $aeadChunkSize = 12;

    private static bool $aeadProtect = false;

    private static bool $useV5Key = false;

    private static bool $allowUnauthenticated = false;

    /**
     * Get preferred hash algorithm.
     *
     * @return HashAlgorithm
     */
    public static function getPreferredHash(): HashAlgorithm
    {
        return self::$preferredHash;
    }

    /**
     * Set preferred hash algorithm.
     *
     * @param HashAlgorithm $hash
     */
    public static function setPreferredHash(HashAlgorithm $hash): void
    {
        self::$preferredHash = $hash;
    }

    /**
     * Get preferred symmetric algorithm.
     *
     * @return SymmetricAlgorithm
     */
    public static function getPreferredSymmetric(): SymmetricAlgorithm
    {
        return self::$preferredSymmetric;
    }

    /**
     * Set preferred symmetric algorithm.
     *
     * @param SymmetricAlgorithm $symmetric
     */
    public static function setPreferredSymmetric(
        SymmetricAlgorithm $symmetric
    ): void {
        self::$preferredSymmetric = $symmetric;
    }

    /**
     * Get preferred compression algorithm.
     *
     * @return CompressionAlgorithm
     */
    public static function getPreferredCompression(): CompressionAlgorithm
    {
        return self::$preferredCompression;
    }

    /**
     * Set preferred compression algorithm.
     *
     * @param CompressionAlgorithm $compression
     */
    public static function setPreferredCompression(
        CompressionAlgorithm $compression
    ): void {
        self::$preferredCompression = $compression;
    }

    /**
     * Get a logger.
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
     * Set a logger.
     *
     * @param LoggerInterface $logger
     */
    public static function setLogger(LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Get S2K hash algorithm.
     *
     * @return HashAlgorithm
     */
    public static function getS2kHash(): HashAlgorithm
    {
        return self::$s2kHash;
    }

    /**
     * Set S2K hash algorithm.
     *
     * @param HashAlgorithm $s2kHash
     */
    public static function setS2kHash(HashAlgorithm $s2kHash): void
    {
        self::$s2kHash = $s2kHash;
    }

    /**
     * Get preferred AEAD algorithm.
     *
     * @return AeadAlgorithm
     */
    public static function getPreferredAead(): AeadAlgorithm
    {
        return self::$preferredAead;
    }

    /**
     * Set preferred AEAD algorithm.
     *
     * @param AeadAlgorithm $algo
     */
    public static function setPreferredAead(AeadAlgorithm $algo): void
    {
        self::$preferredAead = $algo;
    }

    /**
     * Get S2K iteration count byte.
     *
     * @return int
     */
    public static function getS2kItCount(): int
    {
        return self::$s2kItCount;
    }

    /**
     * Set S2K iteration count byte.
     *
     * @param int $s2kItCount
     */
    public static function setS2kItCount(int $s2kItCount): void
    {
        self::$s2kItCount = $s2kItCount;
    }

    /**
     * Get Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode.
     *
     * @return int
     */
    public static function getAeadChunkSize(): int
    {
        return self::$aeadChunkSize;
    }

    /**
     * Set Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode.
     *
     * @param int $aeadChunkSize
     */
    public static function setAeadChunkSize(int $aeadChunkSize): void
    {
        self::$aeadChunkSize = $aeadChunkSize;
    }

    /**
     * Get AEAD protection.
     * Use Authenticated Encryption with Additional Data (AEAD) protection for symmetric encryption.
     *
     * @return bool
     */
    public static function aeadProtect(): bool
    {
        return self::$aeadProtect;
    }

    /**
     * Set AEAD protection.
     *
     * @param bool $protect
     */
    public static function setAeadProtect(bool $protect): void
    {
        self::$aeadProtect = $protect;
    }

    /**
     * Get use V5 key.
     *
     * @return bool
     */
    public static function useV5Key(): bool
    {
        return self::$useV5Key;
    }

    /**
     * Set use V5 key.
     *
     * @param bool $useV5Key
     */
    public static function setUseV5Key(bool $useV5Key): void
    {
        self::$useV5Key = $useV5Key;
    }

    /**
     * Get allow decryption of messages without integrity protection.
     *
     * @return bool
     */
    public static function allowUnauthenticated(): bool
    {
        return self::$allowUnauthenticated;
    }

    /**
     * Set allow decryption of messages without integrity protection.
     *
     * @param bool $allow
     */
    public static function setAllowUnauthenticated(bool $allow): void
    {
        self::$allowUnauthenticated = $allow;
    }
}
