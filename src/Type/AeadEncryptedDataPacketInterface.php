<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\{
    AeadAlgorithm,
    SymmetricAlgorithm,
};

/**
 * Aead encrypted data packet packet interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface AeadEncryptedDataPacketInterface extends EncryptedDataPacketInterface
{
    const ZERO_CHAR = "\x00";

    const AEAD_ENCRYPT = 'encrypt';
    const AEAD_DECRYPT = 'decrypt';

    /**
     * Get version
     *
     * @return int
     */
    function getVersion(): int;

    /**
     * Get symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    function getSymmetric(): SymmetricAlgorithm;

    /**
     * Get AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    function getAead(): ?AeadAlgorithm;

    /**
     * Get chunk size byte
     *
     * @return int
     */
    function getChunkSize(): int;
}
