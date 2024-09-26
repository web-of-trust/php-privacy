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
    PublicKeyInterface,
    PublicKeyPacketInterface,
};

/**
 * OpenPGP public key class
 *
 * @package  OpenPGP
 * @category Key
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicKey extends AbstractKey implements PublicKeyInterface
{
    /**
     * Constructor
     *
     * @param PublicKeyPacketInterface $publicKeyPacket
     * @param array $revocationSignatures
     * @param array $directSignatures
     * @param array $users
     * @param array $subkeys
     * @return self
     */
    public function __construct(
        private readonly PublicKeyPacketInterface $publicKeyPacket,
        array $revocationSignatures = [],
        array $directSignatures = [],
        array $users = [],
        array $subkeys = [],
    )
    {
        parent::__construct(
            $publicKeyPacket,
            $revocationSignatures,
            $directSignatures,
            $users,
            $subkeys,
        );
    }

    /**
     * Read public keys from armored/binary string
     * Return one or multiple key objects
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
            else {
                $publicKeys[] = self::fromPacketList(
                    $packetList->slice($indexes[$i])
                );
            }
        }
        return $publicKeys;
    }

    /**
     * Armor multiple public key.
     *
     * @param array $keys
     * @return string
     */
    public static function armorPublicKeys(array $keys): string
    {
        $keyData = implode(array_map(
            static fn ($key) => $key->toPublic()->getPacketList()->encode(),
            array_filter(
                $keys,
                static fn ($key) => $key instanceof KeyInterface,
            )
        ));
        return empty($keyData) ? '' : Armor::encode(
            ArmorType::PublicKey,
            $keyData,
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
        return self::fromBytes(
            Armor::decode($armored)->assert(ArmorType::PublicKey)->getData()
        );
    }

    /**
     * Read public key from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        return self::fromPacketList(PacketList::decode($bytes));
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
        $keyMap = self::packetListToKeyMap($packetList);
        if (!($keyMap['keyPacket'] instanceof PublicKeyPacketInterface)) {
            throw new \RuntimeException(
                'Key packet is not public key type.'
            );
        }
        return new self(
            $keyMap['keyPacket'],
            $keyMap['revocationSignatures'],
            $keyMap['directSignatures'],
            $keyMap['users'],
            $keyMap['subkeys'],
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKeyPacket(): PublicKeyPacketInterface
    {
        return $this->publicKeyPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function armor(): string
    {
        return Armor::encode(
            ArmorType::PublicKey,
            $this->getPacketList()->encode(),
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
