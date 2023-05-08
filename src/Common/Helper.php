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

use phpseclib3\Math\BigInteger;

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
     * Reads multiprecision integer (MPI) from binary data
     *
     * @param string $bytes
     * @return BigInteger
     */
    public static function readMPI(string $bytes): BigInteger
    {
        $unpacked = unpack('n', substr($bytes,0 , 2));
        $bitLength = reset($unpacked);
        return self::bin2BigInt(substr($bytes, 2, self::bit2ByteLength($bitLength)));
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
}
