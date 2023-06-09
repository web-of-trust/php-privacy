<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * S2k type enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum S2kType: int
{
    case Simple = 0;

    case Salted = 1;

    case Iterated = 3;

    case GNU = 101;

    public function packetLength(): int
    {
        return match($this) {
            self::Simple => 2,
            self::Salted => 10,
            self::Iterated => 11,
            self::GNU => 6,
        };
    }
}
