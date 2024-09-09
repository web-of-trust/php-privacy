<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;
use OpenPGP\Enum\{
    S2kType,
    SymmetricAlgorithm,
};

/**
 * Helper class
 * 
 * @package  OpenPGP
 * @category Common
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class Helper
{
    const EOL = "\n";
    const CRLF = "\r\n";
    const LINE_SPLIT_PATTERN = '/\r\n|\n|\r/';
    const EMPTY_LINE_PATTERN = '/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/';

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
            substr($bytes, 2, self::bit2ByteLength($bitLength))
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
        return ($bitLength + 7) >> 3;
    }

    /**
     * Generate random prefix
     *
     * @param SymmetricAlgorithm $symmetric
     * @return string
     */
    public static function generatePrefix(
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): string
    {
        $size = $symmetric->blockSize();
        $prefix = Random::string($size);
        $repeat = $prefix[$size - 2] . $prefix[$size - 1];
        return $prefix . $repeat;
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
        string $bytes, int $offset = 0, bool $be = true
    ): int
    {
        $unpacked = unpack(
            $be ? 'N' : 'V', substr($bytes, $offset, 4)
        );
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
        string $bytes, int $offset = 0, bool $be = true
    ): int
    {
        $unpacked = unpack(
            $be ? 'n' : 'v', substr($bytes, $offset, 2)
        );
        return (int) array_pop($unpacked);
    }

    /**
     * Get string 2 key
     * 
     * @return S2K
     */
    public static function stringToKey(): S2K
    {
        return new S2K(
            Random::string(S2K::SALT_LENGTH),
            S2kType::Iterated,
            Config::getS2kHash(),
            Config::getS2kItCount()
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
        $sum = array_sum(array_map(
            static fn ($char) => ord($char),
            str_split($text)
        ));
        return pack('n', $sum & 0xffff);
    }

    /**
     * Remove trailing spaces, carriage returns and tabs from each line
     * 
     * @param string $text
     * @return string
     */
    public static function removeTrailingSpaces(string $text): string
    {
        $lines = preg_split(self::LINE_SPLIT_PATTERN, $text);
        $lines = array_map(static fn ($line) => rtrim($line, " \r\t"), $lines);
        return implode(self::EOL, $lines);
    }
}
