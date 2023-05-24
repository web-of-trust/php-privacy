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

use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;
use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * Helper class
 * 
 * @package   OpenPGP
 * @category  Common
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
final class Helper
{
    const MASK_8BITS  = 0xff;
    const MASK_16BITS = 0xffff;
    const MASK_32BITS = 0xffffffff;

    /**
     * Reads multiprecision integer (MPI) from binary data
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
     * Converts binary data to big integer
     *
     * @param string $bytes
     * @return BigInteger
     */
    public static function bin2BigInt(string $bytes): BigInteger
    {
        return new BigInteger(bin2hex($bytes), 16);
    }

    /**
     * Converts bit to byte length
     *
     * @param int $bitLength
     * @return int
     */
    public static function bit2ByteLength(int $bitLength): int
    {
        return ($bitLength + 7) >> 3;
    }

    /**
     * Generates random prefix
     *
     * @param SymmetricAlgorithm $symmetric
     * @return string
     */
    public static function generatePrefix(
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::aes256
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
        return array_values(
            unpack($be ? 'N' : 'V', substr($bytes, $offset, 4))
        )[0];
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
        return array_values(
            unpack($be ? 'n' : 'v', substr($bytes, $offset, 2))
        )[0];
    }

    public static function rightRotate32(int $x, int $s): int
    {
        return self::rightRotate($x & self::MASK_32BITS, $s);
    }

    public static function leftRotate32(int $x, int $s): int
    {
        return self::leftRotate($x & self::MASK_32BITS, $s);
    }

    public static function rightRotate(int $x, int $s): int
    {
        return ($x >> $s) | ($x << (32 - $s));
    }

    public static function leftRotate(int $x, int $s): int
    {
        return ($x << $s) | ($x >> (32 - $s));
    }

    public static function leftShift32(int $x, int $s): int
    {
        return self::leftShift($x & self::MASK_32BITS, $s);
    }

    public static function rightShift32(int $x, int $s): int
    {
        return self::rightShift($x & self::MASK_32BITS, $s);
    }

    public static function leftShift(int $x, int $s)
    {
        return $x << $s;
    }

    public static function rightShift(int $x, int $s)
    {
        return $x >> $s;
    }
}
