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

use OpenPGP\Enum\LiteralFormat;
use OpenPGP\Enum\PacketTag;

/**
 * Implementation of the Modification Detection Code Packet (Tag 19)
 * See RFC 4880, section 5.14
 * 
 * The Modification Detection Code packet contains a SHA-1 hash of plaintext data,
 * which is used to detect message modification.
 * It is only used with a Symmetrically Encrypted Integrity Protected Data packet.
 * The Modification Detection Code packet MUST be the last packet in the plaintext data
 * that is encrypted in the Symmetrically Encrypted Integrity Protected Data packet,
 * and MUST appear in no other place.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class ModificationDetectionCode extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @return self
     */
    public function __construct(private string $data)
    {
        parent::__construct(PacketTag::ModificationDetectionCode);
    }

    /**
     * Read modification detection code packet from byte string
     *
     * @param string $bytes
     * @return ModificationDetectionCode
     */
    public static function fromBytes(string $bytes): ModificationDetectionCode
    {
        return new ModificationDetectionCode($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->data;
    }
}
