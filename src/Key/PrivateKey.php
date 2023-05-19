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
use OpenPGP\Type\PacketListInterface;

/**
 * OpenPGP private key class
 * 
 * @package   OpenPGP
 * @category  Key
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PrivateKey extends AbstractKey
{
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::PrivateKey) {
            throw new \UnexpectedValueException(
                'Armored text not of private key type'
            );
        }
        return self::fromPacketList(
            PacketList::decode($armor->getData())
        );
    }

    public static function fromPacketList(PacketListInterface $packetList): self
    {
        $keyMap = self::readPacketList($packetList);
        $privateKey = new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures']
        );
        $users = array_map(
            static fn ($user) => new User(
                $privateKey,
                $user['userIDPacket'],
                $user['revocationSignatures'],
                $user['selfCertifications'],
                $user['otherCertifications']
            ),
            $keyMap['users']
        );
        $privateKey->setUsers($users);
        $subkeys = array_map(
            static fn ($subkey) => new Subkey(
                $privateKey,
                $subkey['keyPacket'],
                $subkey['revocationSignatures'],
                $subkey['bindingSignatures']
            ),
            $keyMap['subkeys']
        );
        $privateKey->setSubkeys($subkeys);

        return $privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PrivateKey,
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
