<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{HashAlgorithm, S2kType, SymmetricAlgorithm};
use OpenPGP\Type\S2KInterface;
use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;

/**
 * Helper class
 *
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class Helper
{
    const string EOL = "\n";
    const string CRLF = "\r\n";
    const string SPACES = " \r\t";
    const string EOL_PATTERN = '/\r?\n/m';
    const string ZERO_CHAR = "\x00";

    /**
     * Read multiprecision integer (MPI) from binary data
     *
     * @param string $bytes
     * @return BigInteger
     */
    public static function readMPI(string $bytes): BigInteger
    {
        $bitLength = self::bytesToShort($bytes);
        return self::bin2BigInt(
            substr($bytes, 2, self::bit2ByteLength($bitLength)),
        );
    }

    /**
     * Convert binary data to big integer
     *
     * @param string $bytes
     * @return BigInteger
     */
    public static function bin2BigInt(string $bytes): BigInteger
    {
        return new BigInteger($bytes, 256);
    }

    /**
     * Convert bit to byte length
     *
     * @param int $bitLength
     * @return int
     */
    public static function bit2ByteLength(int $bitLength): int
    {
        return $bitLength + 7 >> 3;
    }

    /**
     * Generate random prefix
     *
     * @param SymmetricAlgorithm $symmetric
     * @return string
     */
    public static function generatePrefix(
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
    ): string {
        $size = $symmetric->blockSize();
        $prefix = Random::string($size);
        return implode([$prefix, $prefix[$size - 2], $prefix[$size - 1]]);
    }

    /**
     * Return unsigned long from byte string
     *
     * @param string $bytes
     * @param int $offset
     * @param bool $be
     * @return int
     */
    public static function bytesToLong(
        string $bytes,
        int $offset = 0,
        bool $be = true,
    ): int {
        $unpacked = unpack($be ? "N" : "V", substr($bytes, $offset, 4));
        return (int) array_pop($unpacked);
    }

    /**
     * Return unsigned short from byte string
     *
     * @param string $bytes
     * @param int $offset
     * @param bool $be
     * @return int
     */
    public static function bytesToShort(
        string $bytes,
        int $offset = 0,
        bool $be = true,
    ): int {
        $unpacked = unpack($be ? "n" : "v", substr($bytes, $offset, 2));
        return (int) array_pop($unpacked);
    }

    /**
     * Create string 2 key instance
     *
     * @param S2kType $type
     * @return S2KInterface
     */
    public static function stringToKey(
        S2kType $type = S2kType::Iterated,
    ): S2KInterface {
        if ($type === S2kType::Simple) {
            throw new \RuntimeException(
                "S2k type {$type->name} is unsupported.",
            );
        }
        return $type === S2kType::Argon2
            ? new Argon2S2K(
                self::generatePassword(Argon2S2K::SALT_LENGTH),
                Config::getArgon2Iteration(),
                Config::getArgon2Parallelism(),
                Config::getArgon2MemoryExponent(),
            )
            : new GenericS2K(
                Random::string(GenericS2K::SALT_LENGTH),
                $type,
                Config::getPreferredHash(),
                Config::getS2kItCount(),
            );
    }

    /**
     * Calculate a 16bit sum of a string by adding each character codes modulus 65535
     *
     * @param string $text - To create a sum of
     * @return string - 2 bytes containing the sum of all charcodes % 65535.
     */
    public static function computeChecksum(string $text): string
    {
        $sum = array_sum(
            array_map(static fn($char) => ord($char), str_split($text)),
        );
        return pack("n", $sum & 0xffff);
    }

    /**
     * Generate random password
     *
     * @param int $length
     * @return string
     */
    public static function generatePassword(int $length = 32): string
    {
        return preg_replace_callback(
            "/\*/u",
            static fn() => chr(random_int(40, 126)),
            str_repeat("*", $length),
        );
    }

    /**
     * Remove trailing spaces, carriage returns and tabs from each line
     *
     * @param string $text
     * @return string
     */
    public static function removeTrailingSpaces(string $text): string
    {
        $lines = explode(self::EOL, $text);
        $lines = array_map(
            static fn($line) => rtrim($line, self::SPACES),
            $lines,
        );
        return implode(self::EOL, $lines);
    }

    /**
     * Encode a given integer of length to the openpgp body length specifier
     *
     * @param int $length
     * @return string
     */
    public static function simpleLength(int $length): string
    {
        if ($length < 192) {
            return chr($length);
        } elseif ($length < 8384) {
            return implode([
                chr((($length - 192 >> 8) & 0xff) + 192),
                chr(($length - 192) & 0xff),
            ]);
        } else {
            return implode(["\xff", pack("N", $length)]);
        }
    }

    /**
     * Assert hash algorithm
     *
     * @param HashAlgorithm $hash
     * @return void
     */
    public static function assertHash(HashAlgorithm $hash): void
    {
        switch ($hash) {
            case HashAlgorithm::Unknown:
            case HashAlgorithm::Md5:
            case HashAlgorithm::Sha1:
            case HashAlgorithm::Ripemd160:
                throw new \RuntimeException(
                    "Hash {$hash->name} is unsupported.",
                );
        }
    }

    /**
     * Assert symmetric algorithm
     *
     * @param SymmetricAlgorithm $symmetric
     * @return void
     */
    public static function assertSymmetric(SymmetricAlgorithm $symmetric): void
    {
        switch ($symmetric) {
            case SymmetricAlgorithm::Plaintext:
            case SymmetricAlgorithm::Idea:
            case SymmetricAlgorithm::TripleDes:
            case SymmetricAlgorithm::Cast5:
                throw new \RuntimeException(
                    "Symmetric {$symmetric->name} is unsupported.",
                );
        }
    }
}
