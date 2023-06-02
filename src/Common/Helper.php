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

use phpseclib3\Common\Functions\Strings;
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
        return new BigInteger(Strings::bin2hex($bytes), 16);
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
        $unpacked = unpack($be ? 'N' : 'V', substr($bytes, $offset, 4));
        if (!empty($unpacked)) {
            return array_values($unpacked)[0];
        }
        return 0;
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
        $unpacked = unpack($be ? 'n' : 'v', substr($bytes, $offset, 2));
        if (!empty($unpacked)) {
            return array_values($unpacked)[0];
        }
        return 0;
    }
}
