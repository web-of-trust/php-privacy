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
    SymmetricKeyEncryptedSessionKey
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    EncryptedMessageInterface,
    LiteralMessageInterface,
    PacketListInterface,
    PrivateKeyInterface,
    SessionKeyInterface
};

/**
 * OpenPGP encrypted message class
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class EncryptedMessage extends AbstractMessage implements
    EncryptedMessageInterface
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
        return self::fromBytes(
            Armor::decode($armored)
                ->assert(ArmorType::Message)
                ->getData()
        );
    }

    /**
     * Read message from binary string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $packetList = PacketList::decode($bytes);
        self::assertEncryptedPacket($packetList);
        return new self($packetList);
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptedPacket(): EncryptedDataPacketInterface
    {
        return self::assertEncryptedPacket($this->getPacketList());
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
    ): LiteralMessageInterface {
        $decryptionKeys = array_filter(
            $decryptionKeys,
            static fn($key) => $key instanceof PrivateKeyInterface
        );
        if (empty($decryptionKeys) && empty($passwords)) {
            throw new \InvalidArgumentException(
                "No decryption keys or passwords provided."
            );
        }

        return new LiteralMessage(
            $this->getEncryptedPacket()
                ->decryptWithSessionKey(
                    $this->sessionKey = $this->decryptSessionKey(
                        $decryptionKeys,
                        $passwords
                    )
                )
                ->getPacketList()
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
        array $decryptionKeys,
        array $passwords
    ): SessionKeyInterface {
        $errors = [];
        $sessionKeys = [];
        if (!empty($passwords)) {
            $skeskPacketList = $this->getPacketList()->whereType(
                SymmetricKeyEncryptedSessionKey::class
            );
            foreach ($skeskPacketList as $skesk) {
                foreach ($passwords as $password) {
                    try {
                        $sessionKeys[] = $skesk
                            ->decrypt($password)
                            ->getSessionKey();
                        break;
                    } catch (\Throwable $e) {
                        $errors[] = $e->getMessage();
                    }
                }
            }
        }
        if (empty($sessionKeys) && !empty($decryptionKeys)) {
            $pkeskPacketList = $this->getPacketList()->whereType(
                PublicKeyEncryptedSessionKey::class
            );
            foreach ($pkeskPacketList as $pkesk) {
                foreach ($decryptionKeys as $key) {
                    $keyPacket = $key->getEncryptionKeyPacket();
                    if (
                        $pkesk->getKeyAlgorithm() ===
                            $keyPacket->getKeyAlgorithm() &&
                        strcmp($pkesk->getKeyID(), $keyPacket->getKeyID()) === 0
                    ) {
                        try {
                            $sessionKeys[] = $pkesk
                                ->decrypt($keyPacket)
                                ->getSessionKey();
                            break;
                        } catch (\Throwable $e) {
                            $errors[] = $e->getMessage();
                        }
                    }
                }
            }
        }

        if (empty($sessionKeys)) {
            throw new \RuntimeException(
                implode(PHP_EOL, ["Session key decryption failed.", ...$errors])
            );
        }

        return array_pop($sessionKeys);
    }

    /**
     * Assert packet list contain encrypted data packet
     *
     * @param PacketListInterface $packetList
     * @return EncryptedDataPacketInterface
     */
    private static function assertEncryptedPacket(
        PacketListInterface $packetList
    ): EncryptedDataPacketInterface {
        $encryptedPackets = $packetList
            ->whereType(EncryptedDataPacketInterface::class)
            ->getPackets();
        if (empty($encryptedPackets)) {
            throw new \RuntimeException("No encrypted data packets found.");
        }
        return array_pop($encryptedPackets);
    }
}
