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
 * Implementation of the strange "Marker packet" (Tag 10)
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
    public function toBytes(): string
    {
        return self::MARKER;
    }
}
