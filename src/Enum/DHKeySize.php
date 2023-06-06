<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * DH key size enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum DHKeySize
{
    case L1024_N160;

    case L2048_N224;

    case L2048_N256;

    case L3072_N256;

    public function lSize(): int
    {
        return match($this) {
            self::L1024_N160 => 1024,
            self::L2048_N224 => 2048,
            self::L2048_N256 => 2048,
            self::L3072_N256 => 3072,
        };
    }

    public function nSize(): int
    {
        return match($this) {
            self::L1024_N160 => 160,
            self::L2048_N224 => 224,
            self::L2048_N256 => 256,
            self::L3072_N256 => 256,
        };
    }
}
