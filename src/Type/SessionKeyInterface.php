<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * Session key interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SessionKeyInterface
{
    /**
     * Gets encryption key
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
     * Compute checksum
     * 
     * @return string
     */
    function computeChecksum(): string;

    /**
     * Serializes session key to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
