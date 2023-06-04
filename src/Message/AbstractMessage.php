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

use OpenPGP\Common\{
    Armor,
    Config,
};
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    ArmorableInterface,
    PacketContainerInterface,
    PacketInterface,
    PacketListInterface,
};
use Psr\Log\{
    LoggerAwareInterface,
    LoggerAwareTrait,
    LoggerInterface,
};

/**
 * OpenPGP abstract message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class AbstractMessage implements ArmorableInterface, LoggerAwareInterface, PacketContainerInterface
{
    use LoggerAwareTrait;

    private readonly array $packets;

    /**
     * Constructor
     *
     * @param array $packets
     * @return self
     */
    public function __construct(
        array $packets
    )
    {
        $this->setLogger(Config::getLogger());
        $this->packets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof PacketInterface
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

    /**
     * {@inheritdoc}
     */
    public function getPackets(): array
    {
        return $this->packets;
    }

    /**
     * {@inheritdoc}
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger ?? Config::getLogger();
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->armor();
    }
}
