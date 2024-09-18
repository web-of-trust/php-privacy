<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
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
use OpenPGP\Type\{
    ArmorableInterface,
    PacketContainerInterface,
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
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class AbstractMessage implements ArmorableInterface, LoggerAwareInterface, PacketContainerInterface
{
    use LoggerAwareTrait;

    /**
     * Constructor
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly PacketListInterface $packetList
    )
    {
        $this->setLogger(Config::getLogger());
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::Message,
            $this->getPacketList()->encode()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): PacketListInterface
    {
        return $this->packetList;
    }

    /**
     * {@inheritdoc}
     */
    public function getPackets(): array
    {
        return $this->packetList->getPackets();
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
