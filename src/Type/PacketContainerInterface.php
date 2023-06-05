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

/**
 * Packet container interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface PacketContainerInterface
{
    /**
     * Get contained packets
     *
     * @return array
     */
    function getPackets(): array;

    /**
     * Transform structured data to packet list
     *
     * @return PacketListInterface
     */
    function toPacketList(): PacketListInterface;
}
