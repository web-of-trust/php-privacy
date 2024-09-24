<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * DSA/ElGamal key size enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum DHKeySize
{
    case Normal;

    case Medium;

    case High;

    case VeryHigh;

    /**
     * The size of prime p
     *
     * @return int
     */
    public function lSize(): int
    {
        return match($this) {
            self::Normal => 1024,
            self::Medium => 2048,
            self::High => 2048,
            self::VeryHigh => 3072,
        };
    }

    /**
     * The size of group order q
     *
     * @return int
     */
    public function nSize(): int
    {
        return match($this) {
            self::Normal => 160,
            self::Medium => 224,
            self::High => 256,
            self::VeryHigh => 256,
        };
    }
}
