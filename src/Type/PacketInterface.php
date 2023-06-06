<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\PacketTag;

/**
 * Packet interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface PacketInterface
{
    /**
     * Get packet tag
     * 
     * @return PacketTag
     */
    function getTag(): PacketTag;

    /**
     * Serialize packet to bytes
     * 
     * @return string
     */
    function encode(): string;

    /**
     * Serialize packet data to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
