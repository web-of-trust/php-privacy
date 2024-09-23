<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
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
 * Implementation of the User Attribute Packet (Tag 17)
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
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
            static fn ($attr) => $attr instanceof UserAttributeSubpacket,
        );
    }

    /**
     * {@inheritdoc}
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
        return implode(array_map(
            static fn ($attr): string => $attr->toBytes(),
            $this->attributes
        ));
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
