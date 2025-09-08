<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Key version enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum KeyVersion: int
{
    case V4 = 4;
    case V6 = 6;

    /**
     * Get hash algo name
     *
     * @return string
     */
    public function hashAlgo(): string
    {
        return match ($this) {
            self::V4 => "sha1",
            self::V6 => "sha256",
        };
    }
}
