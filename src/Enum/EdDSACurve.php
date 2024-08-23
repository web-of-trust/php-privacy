<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards;
use phpseclib3\Crypt\EC\Curves\{
    Ed25519,
    Ed448,
};

/**
 * Ed DSA Curve Enum
 * 
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum EdDSACurve
{
    case Ed25519;

    case Ed448;

    /**
     * Get curve
     *
     * @return int
     */
    public function getCurve(): TwistedEdwards
    {
        return match($this) {
            self::Ed25519 => new Ed25519(),
            self::Ed448   => new Ed448(),
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
            self::Ed25519 => Ed25519::SIZE,
            self::Ed448   => Ed448::SIZE,
        };
    }

    /**
     * Get hash algorithm
     *
     * @return HashAlgorithm
     */
    public function hashAlgorithm(): HashAlgorithm
    {
        return match ($this) {
            self::Ed25519 => HashAlgorithm::Sha256,
            self::Ed448   => HashAlgorithm::Sha512,
        };
    }
}
