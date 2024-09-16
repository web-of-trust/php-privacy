<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Type\{
    PacketListInterface,
    SessionKeyInterface,
};

/**
 * Encrypted data packet trait
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
trait EncryptedDataTrait
{
    /**
     * {@inheritdoc}
     */
    public function getEncrypted(): string
    {
        return $this->encrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function getPacketList(): ?PacketListInterface
    {
        return $this->packetList;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketListInterface) {
            return self::encryptPackets($key, $this->packetList, $symmetric);
        }
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function encryptWithSessionKey(
        SessionKeyInterface $sessionKey
    ): self
    {
        return $this->encrypt(
            $sessionKey->getEncryptionKey(),
            $sessionKey->getSymmetric()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function decryptWithSessionKey(
        SessionKeyInterface $sessionKey
    ): self
    {
        return $this->decrypt(
            $sessionKey->getEncryptionKey(),
            $sessionKey->getSymmetric()
        );
    }
}
