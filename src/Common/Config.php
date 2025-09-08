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
    PresetRFC,
    SymmetricAlgorithm,
};

/**
 * Config class
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class Config
{
    const string VERSION = "PHP Privacy v2";
    const string COMMENT = "The PHP OpenPGP library";

    const string CIPHER_MODE = "cfb";
    const string HKDF_ALGO = "sha256";

    const bool AEAD_SUPPORTED = true;
    const int AEAD_CHUNK_SIZE_MIN = 10;
    const int AEAD_CHUNK_SIZE_MAX = 16;

    private static HashAlgorithm $preferredHash = HashAlgorithm::Sha256;

    private static SymmetricAlgorithm $preferredSymmetric = SymmetricAlgorithm::Aes256;

    private static CompressionAlgorithm $preferredCompression = CompressionAlgorithm::Uncompressed;

    private static AeadAlgorithm $preferredAead = AeadAlgorithm::Ocb;

    private static PresetRFC $presetRFC = PresetRFC::RFC4880;

    private static int $s2kItCount = 224;

    private static int $argon2Iteration = 3;

    private static int $argon2Parallelism = 4;

    private static int $argon2MemoryExponent = 16;

    private static int $aeadChunkSize = 12;

    private static bool $aeadProtect = false;

    private static bool $allowUnauthenticated = false;

    private static bool $showVersion = true;

    private static bool $showComment = false;

    private static bool $checksumRequired = false;

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
        Helper::assertHash($hash);
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
        SymmetricAlgorithm $symmetric,
    ): void {
        Helper::assertSymmetric($symmetric);
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
        CompressionAlgorithm $compression,
    ): void {
        self::$preferredCompression = $compression;
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
     * Get preset RFC.
     *
     * @return PresetRFC
     */
    public static function presetRFC(): PresetRFC
    {
        return self::$presetRFC;
    }

    /**
     * Preset RFC4880.
     */
    public static function presetRFC4880(): void
    {
        self::$presetRFC = PresetRFC::RFC4880;
    }

    /**
     * Preset RFC9580.
     */
    public static function presetRFC9580(): void
    {
        self::$presetRFC = PresetRFC::RFC9580;
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
     * Get Argon2 iteration count.
     *
     * @return int
     */
    public static function getArgon2Iteration(): int
    {
        return self::$argon2Iteration;
    }

    /**
     * Set Argon2 iteration count.
     *
     * @param int $argon2Iteration
     */
    public static function setArgon2Iteration(int $argon2Iteration): void
    {
        self::$argon2Iteration = $argon2Iteration;
    }

    /**
     * Get Argon2 parallelismt.
     *
     * @return int
     */
    public static function getArgon2Parallelism(): int
    {
        return self::$argon2Parallelism;
    }

    /**
     * Set Argon2 parallelismt.
     *
     * @param int $argon2Parallelism
     */
    public static function setArgon2Parallelism(int $argon2Parallelism): void
    {
        self::$argon2Parallelism = $argon2Parallelism;
    }

    /**
     * Get Argon2 memory exponent.
     *
     * @return int
     */
    public static function getArgon2MemoryExponent(): int
    {
        return self::$argon2MemoryExponent;
    }

    /**
     * Set Argon2 memory exponent.
     *
     * @param int $argon2MemoryExponent
     */
    public static function setArgon2MemoryExponent(
        int $argon2MemoryExponent,
    ): void {
        self::$argon2MemoryExponent = $argon2MemoryExponent;
    }

    /**
     * Get Chunk Size Byte for Authenticated Encryption with Additional Data (AEAD) mode.
     *
     * @return int
     */
    public static function getAeadChunkSize(): int
    {
        return min(
            max(self::$aeadChunkSize, self::AEAD_CHUNK_SIZE_MIN),
            self::AEAD_CHUNK_SIZE_MAX,
        );
    }

    /**
     * Set Chunk Size Byte for Authenticated Encryption
     * with Additional Data (AEAD) mode.
     *
     * @param int $aeadChunkSize
     */
    public static function setAeadChunkSize(int $aeadChunkSize): void
    {
        self::$aeadChunkSize = min(
            max($aeadChunkSize, self::AEAD_CHUNK_SIZE_MIN),
            self::AEAD_CHUNK_SIZE_MAX,
        );
    }

    /**
     * Get AEAD protection.
     * Use Authenticated Encryption with Additional Data (AEAD)
     * protection for symmetric encryption.
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

    /**
     * Whether to include version header in armored messages.
     *
     * @return bool
     */
    public static function showVersion(): bool
    {
        return self::$showVersion;
    }

    /**
     * Set show version.
     *
     * @param bool $showVersion
     */
    public static function setShowVersion(bool $showVersion): void
    {
        self::$showVersion = $showVersion;
    }

    /**
     * Whether to include comment header in armored messages.
     *
     * @return bool
     */
    public static function showComment(): bool
    {
        return self::$showComment;
    }

    /**
     * Set show comment.
     *
     * @param bool $showComment
     */
    public static function setShowComment(bool $showComment): void
    {
        self::$showComment = $showComment;
    }

    /**
     * Whether checksum required in armored messages.
     *
     * @return bool
     */
    public static function checksumRequired(): bool
    {
        return self::$checksumRequired;
    }

    /**
     * Set checksum required.
     *
     * @param bool $checksumRequired
     */
    public static function setChecksumRequired(bool $checksumRequired): void
    {
        self::$checksumRequired = $checksumRequired;
    }
}
