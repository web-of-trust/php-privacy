<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use OpenPGP\Cryptor\Aead\{AeadCipher, EAX, GCM, OCB};

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

    /**
     * Get block length
     *
     * @return int
     */
    public function blockLength(): int
    {
        return match ($this) {
            self::Eax, self::Ocb, self::Gcm => 16,
        };
    }

    /**
     * Get iv length
     *
     * @return int
     */
    public function ivLength(): int
    {
        return match ($this) {
            self::Eax => 16,
            self::Ocb => 15,
            self::Gcm => 12,
        };
    }

    /**
     * Get tag length
     *
     * @return int
     */
    public function tagLength(): int
    {
        return match ($this) {
            self::Eax, self::Ocb, self::Gcm => 16,
        };
    }

    /**
     * Get aead cipher engine
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return AeadCipher
     */
    public function cipherEngine(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): AeadCipher {
        return match ($this) {
            self::Eax => new EAX($key, $symmetric),
            self::Ocb => new OCB($key, $symmetric),
            self::Gcm => new GCM($key, $symmetric),
        };
    }
}
