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
 * Implementation of the Trust Packet (Tag 12)
 *
 * See RFC 9580, section 5.10.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Trust extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $levelAndTrustAmount
     * @return self
     */
    public function __construct(private readonly string $levelAndTrustAmount)
    {
        parent::__construct(PacketTag::Trust);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->levelAndTrustAmount;
    }
}
