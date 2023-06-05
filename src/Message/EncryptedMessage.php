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
use OpenPGP\Packet\{
    PacketList,
    PublicKeyEncryptedSessionKey,
    SymEncryptedSessionKey,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    EncryptedMessageInterface,
    LiteralMessageInterface,
    PrivateKeyInterface,
    SessionKeyInterface,
};

/**
 * OpenPGP encrypted message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class EncryptedMessage extends AbstractMessage implements EncryptedMessageInterface
{
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
        $packets = PacketList::decode($armor->getData())->getPackets();
        self::validatePackets($packets);
        return new self($packets);
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
            $decryptionKeys, static fn ($key) => $key instanceof PrivateKeyInterface
        );
        if (empty($decryptionKeys) && empty($passwords)) {
            throw new \InvalidArgumentException(
                'No decryption keys or passwords provided.'
            );
        }

        $packets = $this->getPackets();
        $encryptedPackets = self::validatePackets($packets);

        $encryptedPacket = array_pop($encryptedPackets);
        $sessionKey = $this->decryptSessionKey($decryptionKeys, $passwords);
        $decryptedPacket = $encryptedPacket->decryptWithSessionKey(
            $sessionKey
        );

        return new LiteralMessage(
            $decryptedPacket->getPacketList()->getPackets()
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
        $packets = $this->getPackets();
        $sessionKeys = [];
        if (!empty($passwords)) {
            $this->getLogger()->debug(
                'Decrypt session keys by passwords.', $passwords
            );
            $skeskPackets = array_filter(
                $packets,
                static fn ($packet) => $packet instanceof SymEncryptedSessionKey
            );
            foreach ($skeskPackets as $skesk) {
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
            $this->getLogger()->debug(
                'Decrypt session keys by public keys.', $decryptionKeys
            );
            $pkeskPackets = array_filter(
                $packets,
                static fn ($packet) => $packet instanceof PublicKeyEncryptedSessionKey
            );
            foreach ($pkeskPackets as $pkesk) {
                foreach ($decryptionKeys as $key) {
                    $keyPacket = $key->getEncryptionKeyPacket();
                    if ($pkesk->getPublicKeyAlgorithm() === $keyPacket->getKeyAlgorithm() &&
                        $pkesk->getPublicKeyID() === $keyPacket->getKeyID()) {
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

    private static function validatePackets(array $packets): array
    {
        $encryptedPackets = array_filter(
            $packets,
            static fn ($packet) => $packet instanceof EncryptedDataPacketInterface
        );
        if (empty($encryptedPackets)) {
            throw new \UnexpectedValueException(
                'No encrypted data packets found.'
            );
        }
        return $encryptedPackets;
    }
}
