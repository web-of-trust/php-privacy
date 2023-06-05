<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use OpenPGP\Common\Armor;
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\PacketList;
use OpenPGP\Type\{
    KeyInterface,
    PacketListInterface,
    PublicKeyPacketInterface,
};

/**
 * OpenPGP public key class
 * 
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicKey extends AbstractKey
{
    /**
     * Constructor
     *
     * @param PublicKeyPacketInterface $keyPacket
     * @param array $revocationSignatures
     * @param array $directSignatures
     * @param array $users
     * @param array $subkeys
     * @return self
     */
    public function __construct(
        PublicKeyPacketInterface $keyPacket,
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = []
    )
    {
        parent::__construct(
            $keyPacket,
            $revocationSignatures,
            $directSignatures,
            $users,
            $subkeys
        );
    }

    /**
     * Read public key from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::PublicKey) {
            throw new \UnexpectedValueException(
                'Armored text not of public key type.'
            );
        }
        return self::fromPacketList(
            PacketList::decode($armor->getData())
        );
    }

    /**
     * Read public key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(
        PacketListInterface $packetList
    ): self
    {
        $keyStruct = self::readPacketList($packetList);
        if (!($keyStruct['keyPacket'] instanceof PublicKeyPacketInterface)) {
            throw new \UnexpectedValueException(
                'Key packet is not public key type.'
            );
        }
        $publicKey = new self(
            $keyStruct['keyPacket'],
            $keyStruct['revocationSignatures'],
            $keyStruct['directSignatures']
        );
        self::applyKeyStructure($publicKey, $keyStruct);

        return $publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PublicKey,
            $this->toPacketList()->encode()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toPublic(): KeyInterface
    {
        return $this;
    }
}
