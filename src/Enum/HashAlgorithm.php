<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Hash algorithm enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum HashAlgorithm: int
{
    case Unknown = 0;

	case Md5 = 1;

	case Sha1 = 2;

	case Ripemd160 = 3;

	case Sha256 = 8;

	case Sha384 = 9;

	case Sha512 = 10;

	case Sha224 = 11;

    public function digestSize(): int
    {
        return match($this) {
            self::Unknown => 0,
            self::Md5 => 16,
            self::Sha1 => 20,
            self::Ripemd160 => 20,
            self::Sha256 => 32,
            self::Sha384 => 48,
            self::Sha512 => 64,
            self::Sha224 => 28,
        };
    }
}
