<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Post-quantum SLH-DSA Enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum SlhDSA
{
    case SlhDsaShake128s;

    case SlhDsaShake128f;

    case SlhDsaShake256s;

    /**
     * Get public size
     *
     * @return int
     */
    public function publicSize(): int
    {
        return match ($this) {
            self::SlhDsaShake128s => 32,
            self::SlhDsaShake128f => 32,
            self::SlhDsaShake256s => 64,
        };
    }

    /**
     * Get secret size
     *
     * @return int
     */
    public function secretSize(): int
    {
        return match ($this) {
            self::SlhDsaShake128s => 64,
            self::SlhDsaShake128f => 64,
            self::SlhDsaShake256s => 128,
        };
    }

    /**
     * Get signature size
     *
     * @return int
     */
    public function signatureSize(): int
    {
        return match ($this) {
            self::SlhDsaShake128s => 7856,
            self::SlhDsaShake128f => 17088,
            self::SlhDsaShake256s => 29792,
        };
    }
}
