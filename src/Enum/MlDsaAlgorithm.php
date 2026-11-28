<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Post-quantum ML-DSA Algorithm Enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum MlDsaAlgorithm
{
    case MlDsa65;

    case MlDsa87;

    /**
     * Get public size
     *
     * @return int
     */
    public function publicSize(): int
    {
        return match ($this) {
            self::MlDsa65 => 1952,
            self::MlDsa87 => 2592,
        };
    }

    /**
     * Get secret size
     *
     * @return int
     */
    public function secretSize(): int
    {
        return 32;
    }

    /**
     * Get signature size
     *
     * @return int
     */
    public function signatureSize(): int
    {
        return match ($this) {
            self::MlDsa65 => 3309,
            self::MlDsa87 => 4627,
        };
    }
}
