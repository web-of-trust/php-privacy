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
    KeyPacketInterface,
    PacketListInterface
};

/**
 * OpenPGP public key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicKey extends AbstractKey
{
    /**
     * Reads public key from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::PublicKey) {
            throw new \UnexpectedValueException(
                'Armored text not of public key type'
            );
        }
        return self::fromPacketList(
            PacketList::decode($armor->getData())
        );
    }

    /**
     * Reads public key from packet list
     *
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function fromPacketList(PacketListInterface $packetList): self
    {
        $keyMap = self::readPacketList($packetList);
        if (!($keyMap['keyPacket'] instanceof KeyPacketInterface)) {
            throw new \UnexpectedValueException(
                'Key packet is not key type'
            );
        }
        $publicKey = new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures']
        );
        $users = array_map(
            static fn ($user) => new User(
                $publicKey,
                $user['userIDPacket'],
                $user['revocationSignatures'],
                $user['selfCertifications'],
                $user['otherCertifications']
            ),
            $keyMap['users']
        );
        $publicKey->setUsers($users);
        $subkeys = array_map(
            static fn ($subkey) => new Subkey(
                $publicKey,
                $subkey['keyPacket'],
                $subkey['revocationSignatures'],
                $subkey['bindingSignatures']
            ),
            $keyMap['subkeys']
        );
        $publicKey->setSubkeys($subkeys);

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