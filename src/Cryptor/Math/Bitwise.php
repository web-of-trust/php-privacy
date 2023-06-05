<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Math;

/**
 * Bitwise class
 * 
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
final class Bitwise
{
    const MASK_8BITS  = 0xff;
    const MASK_16BITS = 0xffff;
    const MASK_32BITS = 0xffffffff;

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

    public static function leftShift(int $x, int $s): int
    {
        return $x << $s;
    }

    public static function rightShift(int $x, int $s): int
    {
        return $x >> $s;
    }
}
