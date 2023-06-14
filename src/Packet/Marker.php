<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;

/**
 * Implementation of the strange "Marker packet" (Tag 10)
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Marker extends AbstractPacket
{
    const MARKER = 'PGP';

    /**
     * Constructor
     *
     * @return self
     */
    public function __construct()
    {
        parent::__construct(PacketTag::Marker);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        return new self();
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return self::MARKER;
    }
}
