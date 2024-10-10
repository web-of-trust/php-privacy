<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib3\Crypt\Random;

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
     * Get payload size
     *
     * @return int
     */
    public function payloadSize(): int
    {
        return match ($this) {
            self::Curve25519 => 32,
            self::Curve448 => 56,
        };
    }

    /**
     * Get kek size
     *
     * @return KekSize
     */
    public function kekSize(): KekSize
    {
        return match ($this) {
            self::Curve25519 => KekSize::Normal,
            self::Curve448 => KekSize::High,
        };
    }

    /**
     * Get hkdf hash name
     *
     * @return string
     */
    public function hkdfHash(): string
    {
        return match ($this) {
            self::Curve25519 => "sha256",
            self::Curve448 => "sha512",
        };
    }

    /**
     * Get hkdf info
     *
     * @return string
     */
    public function hkdfInfo(): string
    {
        return match ($this) {
            self::Curve25519 => "OpenPGP X25519",
            self::Curve448 => "OpenPGP X448",
        };
    }

    /**
     * Generate secret key
     *
     * @return string
     */
    public function generateSecretKey(): string
    {
        $size = $this->payloadSize();
        do {
            $secret = Random::string($size);
            if ($this === self::Curve25519) {
                /// The lowest three bits must be 0
                $secret[0] = $secret[0] & "\xf8";
                // The highest bit must be 0 & the second highest bit must be 1
                $secret[$size - 1] = ($secret[$size - 1] & "\x7f") | "\x40";
            }
            else {
                // The two least significant bits of the first byte to 0
                $secret[0] = $secret[0] & "\xfc";
                // The most significant bit of the last byte to 1
                $secret[$size - 1] = $secret[$size - 1] | "\x80";
            }
            $d = Helper::bin2BigInt($secret);
        } while ($d->getLengthInBytes() !== $size);
        return $secret;
    }
}
