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
 * Aead algorithm enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum AeadAlgorithm: int
{
    case Eax = 1;

    case Ocb = 2;

    case Gcm = 100;

    public function blockLength(): int
    {
        return match($this) {
            self::Eax => 16,
            self::Ocb => 16,
            self::Gcm => 16,
        };
    }

    public function ivLength(): int
    {
        return match($this) {
            self::Eax => 16,
            self::Ocb => 15,
            self::Gcm => 12,
        };
    }

    public function tagLength(): int
    {
        return match($this) {
            self::Eax => 16,
            self::Ocb => 16,
            self::Gcm => 16,
        };
    }
}
