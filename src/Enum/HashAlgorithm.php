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
 * HashAlgorithm enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum HashAlgorithm: int
{
    case UNKNOWN = 0;

	case MD5 = 1;

	case SHA1 = 2;

	case RIPEMD160 = 3;

	case SHA256 = 8;

	case SHA384 = 9;

	case SHA512 = 10;

	case SHA224 = 11;

    public function digestSize(): int
    {
        return match($this) {
            HashAlgorithm::MD5 => 16,
            HashAlgorithm::SHA1 => 20,
            HashAlgorithm::RIPEMD160 => 20,
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
            HashAlgorithm::SHA224 => 28,
        };
    }
}
