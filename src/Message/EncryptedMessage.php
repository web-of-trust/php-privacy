<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use OpenPGP\Common\Armor;
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\{LiteralData, PacketList};
use OpenPGP\Type\{
    ArmorableInterface,
    EncryptedMessageInterface,
    PacketContainerInterface,
    PacketInterface,
    PacketListInterface
};

/**
 * OpenPGP encrypted message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class EncryptedMessage implements ArmorableInterface, PacketContainerInterface, EncryptedMessageInterface
{
    private readonly array $packets;

    /**
     * Constructor
     *
     * @param array $signaturePackets
     * @return self
     */
    public function __construct(
        array $packets,
    )
    {
        $this->packets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof PacketInterface
        );
    }

    /**
     * Reads message from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::Message) {
            throw new \UnexpectedValueException(
                'Armored text not of message type'
            );
        }
        return new self(
            PacketList::decode($armor->getData())->toArray()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::Message,
            $this->toPacketList()->encode()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPacketList(): PacketListInterface
    {
        return new PacketList($this->packets);
    }
}
