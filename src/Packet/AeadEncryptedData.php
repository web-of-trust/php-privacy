<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{
    AeadAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    SessionKeyInterface,
    PacketListInterface,
};

/**
 * AEAD Protected Data Packet class
 * 
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet(Tag 20)
 * See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis#name-aead-encrypted-data-packet-
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class AeadEncryptedData extends AbstractPacket implements EncryptedDataPacketInterface
{
    use EncryptedDataTrait;

    const VERSION = 1;

    /**
     * Constructor
     *
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSize
     * @param string $iv
     * @param string $encrypted
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly SymmetricAlgorithm $symmetric,
        private readonly AeadAlgorithm $aead,
        private readonly int $chunkSize,
        private readonly string $iv,
        private readonly string $encrypted,
        private readonly ?PacketListInterface $packetList = null
    )
    {
        parent::__construct(PacketTag::AeadEncryptedData);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number.
        // The only currently defined version is 1.
        $version = ord($bytes[$offset++]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the AEAD-encrypted data packet is not supported.",
          );
        }

        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
        $aead = AeadAlgorithm::from(ord($bytes[$offset++]));
        $chunkSize = ord($bytes[$offset++]);
        $iv = substr($bytes, $offset, $aead->ivLength());
        $offset += $aead->ivLength();
        $encrypted = substr($bytes, $offset);

        return new self(
            $symmetric,
            $aead,
            $chunkSize,
            $iv,
            $encrypted
        );
    }

    /**
     * Encrypt packet list
     *
     * @param string $key
     * @param PacketListInterface $packetList
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param int $chunkSize
     * @return self
     */
    public static function encryptPackets(
        string $key,
        PacketListInterface $packetList,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        AeadAlgorithm $aead = AeadAlgorithm::Eax,
        int $chunkSize = 12
    ): self
    {
        throw new \RuntimeException(
            'AEAD encryption is not supported.'
        );
    }

    /**
     * Encrypt packet list with session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function encryptPacketsWithSessionKey(
        SessionKeyInterface $sessionKey, PacketListInterface $packetList
    ): self
    {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packetList,
            $sessionKey->getSymmetric()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::VERSION),
            chr($this->symmetric->value),
            chr($this->aead->value),
            chr($this->chunkSize),
            $this->iv,
            $this->encrypted
        ]);
    }

    /**
     * Get symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    public function getSymmetricAlgorithm(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * Get AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    public function getAeadAlgorithm(): AeadAlgorithm
    {
        return $this->aead;
    }

    /**
     * Get chunk size byte
     *
     * @return int
     */
    public function getChunkSize(): int
    {
        return $this->chunkSize;
    }

    /**
     * Get initialization vector
     * 
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        }
        else {
            throw new \RuntimeException(
                'AEAD decryption is not supported.'
            );
        }
    }
}
