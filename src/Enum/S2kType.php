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
    /**
     * Simple S2K directly hashes the string to produce the key data.
     */
    case Simple = 0;

    /**
     * Salted S2K includes a "salt" value in the S2K Specifier -- some arbitrary data --
     * that gets hashed along with the passphrase string to help prevent dictionary attacks.
     */
    case Salted = 1;

    /**
     * Iterated and Salted S2K includes both a salt and an octet count.
     * The salt is combined with the passphrase, and the resulting value is repeated and then hashed.
     */
    case Iterated = 3;

    /**
     * This S2K method hashes the passphrase using Argon2, as specified in RFC9106.
     * This provides memory hardness, further protecting the passphrase against brute-force attacks.
     */
    case Argon2 = 4;

    case GNU = 101;

    public function packetLength(): int
    {
        return match($this) {
            self::Simple => 2,
            self::Salted => 10,
            self::Iterated => 11,
            self::Argon2 => 20,
            self::GNU => 6,
        };
    }
}
