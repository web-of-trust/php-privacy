<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * Session key interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SessionKeyInterface
{
    /**
     * Get encryption key
     *
     * @return string
     */
    function getEncryptionKey(): string;

    /**
     * Get algorithm to encrypt the message with
     *
     * @return SymmetricAlgorithm
     */
    function getSymmetric(): SymmetricAlgorithm;

    /**
     * Checksum the encryption key
     * 
     * @param string $checksum
     * @return string
     */
    function checksum(string $checksum): self;

    /**
     * Compute checksum
     * 
     * @return string
     */
    function computeChecksum(): string;

    /**
     * Serialize session key to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
