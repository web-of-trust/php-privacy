<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\S2kType;

/**
 * String-to-key interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface S2KInterface
{
    /**
     * Get S2K type
     *
     * @return S2kType
     */
    function getType(): S2kType;

    /**
     * Get salt
     *
     * @return string
     */
    function getSalt(): string;

    /**
     * Get packet length
     *
     * @return int
     */
    function getLength(): int;

    /**
     * Serialize s2k information to binary string
     * 
     * @return string
     */
    function toBytes(): string;

    /**
     * Produce a key using the specified passphrase and the defined hash algorithm
     * 
     * @param string $passphrase
     * @param int $length
     * @return string
     */
    function produceKey(string $passphrase, int $length): string;
}
