<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;

/**
 * Implementation of the Trust Packet (Tag 12)
 * See https://tools.ietf.org/html/rfc4880#section-5.10
 * 
 * The Trust packet is used only within keyrings and is not normally exported.
 * Trust packets contain data that record the user's specifications
 * of which key holders are trustworthy introducers, along with other information
 * that implementing software uses for trust information.
 * The format of Trust packets is defined by a given implementation.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Trust extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $levelAndTrustAmount
     * @return self
     */
    public function __construct(private string $levelAndTrustAmount)
    {
        parent::__construct(PacketTag::Trust);
    }

    /**
     * Read trust packet from byte string
     *
     * @param string $bytes
     * @return Trust
     */
    public static function fromBytes(string $bytes): Trust
    {
        return new Trust($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->levelAndTrustAmount;
    }
}
