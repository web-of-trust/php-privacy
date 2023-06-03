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
use OpenPGP\Type\UserIDPacketInterface;

/**
 * User attribute packet class
 * 
 * Implementation of the User ID Packet (Tag 13)
 * A User ID packet consists of UTF-8 text that is intended to represent
 * the name and email address of the key holder.
 * By convention, it includes an RFC2822 mail name-addr,
 * but there are no restrictions on its content.
 * The packet length in the header specifies the length of the User ID.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class UserAttribute extends AbstractPacket implements UserIDPacketInterface
{
    private readonly array $attributes;

    /**
     * Constructor
     *
     * @param array $attributes
     * @return self
     */
    public function __construct(array $attributes)
    {
        parent::__construct(PacketTag::UserAttribute);
        $this->attributes = array_filter(
            $attributes,
            static fn ($attr) => $attr instanceof UserAttributeSubpacket
        );
    }

    /**
     * Read user attributes from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return new self(
            SubpacketReader::readUserAttributes($bytes)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode(
            array_map(static fn ($attr) => $attr->toBytes(), $this->attributes)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        $bytes = $this->toBytes();
        return implode([
            "\xd1",
            pack('N', strlen($bytes)),
            $bytes,
        ]);
    }

    /**
     * Get user attributes
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }
}
