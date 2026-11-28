<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Post-quantum ML-KEM Algorithm Enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum MlKemAlgorithm
{
    case MlKem768;

    case MlKem1024;

    /**
     * Get encapsulation size
     *
     * @return int
     */
    public function encapsulationSize(): int
    {
        return match ($this) {
            self::MlKem768 => 1184,
            self::MlKem1024 => 1568,
        };
    }

    /**
     * Get decapsulation size
     *
     * @return int
     */
    public function decapsulationSize(): int
    {
        return 64;
    }

    /**
     * Get ciphertext size
     *
     * @return int
     */
    public function ciphertextSize(): int
    {
        return match ($this) {
            self::MlKem768 => 1088,
            self::MlKem1024 => 1568,
        };
    }

    /**
     * Get shared secret size
     *
     * @return int
     */
    public function sharedSecretSize(): int
    {
        return 32;
    }
}
