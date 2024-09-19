<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Key;

use OpenPGP\Common\Armor;
use OpenPGP\Enum\{
    ArmorType,
    PacketTag,
};
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
        array $subkeys = [],
    )
    {
        parent::__construct(
            $keyPacket,
            $revocationSignatures,
            $directSignatures,
            $users,
            $subkeys,
        );
    }

    /**
     * Read public keys from armored/binary string
     * Return one or multiple key objects.
     *
     * @param string $data
     * @param bool $armored
     * @return array
     */
    public static function readPublicKeys(
        string $data, bool $armored = true
    ): array
    {
        if ($armored) {
            $armor = Armor::decode($data)->assert(ArmorType::PublicKey);
            $data = $armor->getData();
        }

        $publicKeys = [];
        $packetList = PacketList::decode($data);
        $indexes = $packetList->indexOfTags(PacketTag::PublicKey);
        for ($i = 0, $count = count($indexes); $i < $count; $i++) {
            if (!empty($indexes[$i + 1])) {
                $length = $indexes[$i + 1] - $indexes[$i];
                $publicKeys[] = self::fromPacketList(
                    $packetList->slice($indexes[$i], $length)
                );
            }
        }
        return $publicKeys;
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
        return self::fromBytes($armor->getData());
    }

    /**
     * Read public key from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return self::fromPacketList(
            PacketList::decode($bytes)
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
            throw new \RuntimeException(
                'Key packet is not public key type.'
            );
        }
        $publicKey = new self(
            $keyStruct['keyPacket'],
            $keyStruct['revocationSignatures'],
            $keyStruct['directSignatures'],
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
            $this->getPacketList()->encode()
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
