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

use \DateTime;
use OpenPGP\Enum\PacketTag;

/**
 * Public key packet class
 * 
 * PublicKey represents an OpenPGP public key packet.
 * See RFC 4880, section 5.5.2.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicKey extends AbstractPacket implements KeyPacketInterface
{
	const KEY_VERSION = 4;

    /**
     * Constructor
     *
     * @param DateTime $creationTime
     * @return self
     */
    public function __construct(private DateTime $creationTime)
    {
        parent::__construct(PacketTag::PublicKey);
    }
}
