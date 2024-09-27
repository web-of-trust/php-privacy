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
 * Packet list interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface PacketListInterface extends
    \ArrayAccess,
    \IteratorAggregate,
    \Countable
{
    /**
     * Get array packets
     *
     * @return array
     */
    function getPackets(): array;

    /**
     * Serialize packets to bytes
     *
     * @return string
     */
    function encode(): string;

    /**
     * Filter packets by tag
     *
     * @param PacketTag $tag
     * @return self
     */
    function whereTag(PacketTag $tag): self;

    /**
     * Filter packets by type (class)
     *
     * @param string $type
     * @return self
     */
    function whereType(string $type): self;

    /**
     * Extract a slice of the packets
     *
     * @param int $offset
     * @param int $length
     * @return self
     */
    function slice(int $offset, ?int $length = null): self;

    /**
     * Return array of found indices by tags
     *
     * @param $tags
     * @return array
     */
    function indexOfTags(...$tags): array;
}
