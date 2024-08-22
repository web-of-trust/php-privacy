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
     * @return int
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
}
