<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Common;

use OpenPGP\Enum\{
    S2kType,
    SymmetricAlgorithm,
};
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
     * Create string 2 key instance
     * 
     * @param S2kType $type
     * @return S2KInterface
     */
    public static function stringToKey(
        S2kType $type = S2kType::Iterated
    ): S2KInterface
    {
        return $type === S2kType::Argon2 ? 
            new Argon2S2K(
                self::generatePassword(Argon2S2K::SALT_LENGTH),
                Config::getArgon2Iteration(),
                Config::getArgon2Parallelism(),
                Config::getArgon2MemoryExponent(),
            ) : new GenericS2K(
                self::generatePassword(GenericS2K::SALT_LENGTH),
                $type,
                Config::getS2kHash(),
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
        $sum = array_sum(array_map(
            static fn ($char) => ord($char),
            str_split($text)
        ));
        return pack('n', $sum & 0xffff);
    }

    /**
     * Generate random password
     * 
     * @return string
     */
    public static function generatePassword(int $length = 32): string 
    {
        return preg_replace_callback(
            '/\*/u',
            fn () => chr(random_int(33, 126)),
            str_repeat('*', $length)
        );
    }
}
