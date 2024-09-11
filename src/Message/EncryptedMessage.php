<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use OpenPGP\Common\Armor;
use OpenPGP\Enum\ArmorType;
use OpenPGP\Packet\{
    PacketList,
    PublicKeyEncryptedSessionKey,
    SymEncryptedSessionKey,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    EncryptedMessageInterface,
    LiteralMessageInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SessionKeyInterface,
};

/**
 * OpenPGP encrypted message class
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EncryptedMessage extends AbstractMessage implements EncryptedMessageInterface
{
    private ?SessionKeyInterface $sessionKey = null;

    /**
     * Read message from armored string
     *
     * @param string $armored
     * @return self
     */
    public static function fromArmored(string $armored): self
    {
        $armor = Armor::decode($armored);
        if ($armor->getType() !== ArmorType::Message) {
            throw new \UnexpectedValueException(
                'Armored text not of message type.'
            );
        }
        return self::fromBytes($armor->getData());
    }

    /**
     * Read message from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $packetList = PacketList::decode($bytes);
        self::validatePacketList($packetList);
        return new self($packetList);
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptedPacket(): EncryptedDataPacketInterface
    {
        $encryptedPackets = self::validatePacketList(
            $this->getPacketList()
        );
        return array_pop($encryptedPackets);
    }

    /**
     * {@inheritdoc}
     */
    public function getSessionKey(): ?SessionKeyInterface
    {
        return $this->sessionKey;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        array $decryptionKeys = [],
        array $passwords = []
    ): LiteralMessageInterface
    {
        $decryptionKeys = array_filter(
            $decryptionKeys,
            static fn ($key) => $key instanceof PrivateKeyInterface
        );
        if (empty($decryptionKeys) && empty($passwords)) {
            throw new \InvalidArgumentException(
                'No decryption keys or passwords provided.'
            );
        }

        $decryptedPacket = $this->getEncryptedPacket()->decryptWithSessionKey(
            $this->sessionKey = $this->decryptSessionKey(
                $decryptionKeys, $passwords
            )
        );

        return new LiteralMessage(
            $decryptedPacket->getPacketList()
        );
    }

    /**
     * Decrypt session key.
     *
     * @param array $decryptionKeys
     * @param array $passwords
     * @return SessionKeyInterface
     */
    private function decryptSessionKey(
        array $decryptionKeys, array $passwords
    ): SessionKeyInterface
    {
        $sessionKeys = [];
        if (!empty($passwords)) {
            $this->getLogger()->warning(
                'Decrypt session keys by passwords.'
            );
            $skeskPacketList = $this->getPacketList()->whereType(
                SymEncryptedSessionKey::class
            );
            foreach ($skeskPacketList as $skesk) {
                foreach ($passwords as $password) {
                    try {
                        $sessionKeys[] = $skesk->decrypt($password)->getSessionKey();
                        break;
                    }
                    catch (\Throwable $e) {
                        $this->getLogger()->error($e);
                    }
                }
            }
        }
        if (empty($sessionKeys) && !empty($decryptionKeys)) {
            $this->getLogger()->warning(
                'Decrypt session keys by public keys.'
            );
            $pkeskPacketList = $this->getPacketList()->whereType(
                PublicKeyEncryptedSessionKey::class
            );
            foreach ($pkeskPacketList as $pkesk) {
                foreach ($decryptionKeys as $key) {
                    $keyPacket = $key->getEncryptionKeyPacket();
                    if ($pkesk->getPublicKeyAlgorithm() === $keyPacket->getKeyAlgorithm() &&
                        strcmp($pkesk->getPublicKeyID(), $keyPacket->getKeyID()) === 0) {
                        try {
                            $sessionKeys[] = $pkesk->decrypt($keyPacket)->getSessionKey();
                            break;
                        }
                        catch (\Throwable $e) {
                            $this->getLogger()->error($e);
                        }
                    }
                }
            }
        }

        if (empty($sessionKeys)) {
            throw new \UnexpectedValueException(
                'Session key decryption failed.'
            );
        }

        return array_pop($sessionKeys);
    }

    private static function validatePacketList(
        PacketListInterface $packetList
    ): array
    {
        $encryptedPackets = $packetList->whereType(
            EncryptedDataPacketInterface::class
        )->getPackets();
        if (empty($encryptedPackets)) {
            throw new \UnexpectedValueException(
                'No encrypted data packets found.'
            );
        }
        return $encryptedPackets;
    }
}
