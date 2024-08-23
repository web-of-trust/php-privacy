<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib3\Crypt\EC\BaseCurves\Montgomery;
use phpseclib3\Crypt\EC\Curves\{
    Curve25519,
    Curve448,
};

/**
 * Montgomery Curve Enum
 * 
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum MontgomeryCurve
{
    case Curve25519;

    case Curve448;

    /**
     * Get curve
     *
     * @return Montgomery
     */
    public function getCurve(): Montgomery
    {
        return match($this) {
            self::Curve25519 => new Curve25519(),
            self::Curve448   => new Curve448(),
        };
    }

    /**
     * Get payload size
     *
     * @return int
     */
    public function payloadSize(): int
    {
        return match ($this) {
            self::Curve25519 => 32,
            self::Curve448   => 56,
        };
    }

    /**
     * Get hash algorithm name
     *
     * @return string
     */
    public function hashAlgorithm(): string
    {
        return match ($this) {
            self::Curve25519 => 'sha256',
            self::Curve448   => 'sha512',
        };
    }

    /**
     * Get hkdf info
     *
     * @return string
     */
    public function hkdfInfo(): string
    {
        return match($this) {
            self::Curve25519 => 'OpenPGP X25519',
            self::Curve448   => 'OpenPGP X448',
        };
    }

    /**
     * Get symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    public function symmetricAlgorithm(): SymmetricAlgorithm
    {
        return match($this) {
            self::Curve25519 => SymmetricAlgorithm::Aes128,
            self::Curve448   => SymmetricAlgorithm::Aes256,
        };
    }
}
